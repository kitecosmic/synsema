# Config, environment & secrets

Synsema is **easy to develop** (one repo, dev defaults, prod by environment) and
**secure by design**: a tainted `secret` type that you *use* but cannot *read* —
LLM-proof, with **zero cost on the hot path**.

## Reading configuration

Define any variable once (in a `.env` file or the process environment) and read it
by name. There are two ways to read, depending on sensitivity:

```
let port be env("PORT", 8080)                 -- plain string config
let key  be secret("STRIPE_API_KEY")          -- opaque, redacted everywhere
```

| Builtin | Returns | Capability |
|---|---|---|
| `env(name, default?)` | plain text | `require env("NAME")` |
| `secret(name, default?)` | an opaque `secret` (from config) | `require secret("NAME")` |
| `as_secret(value, label?)` | seal a **runtime** value as a `secret` | none (pure) — see [below](#sealing-a-runtime-value-as_secret) |

Both are **deny-by-default and scoped by name**, just like `net`/`file`. Reading a
variable you didn't declare fails with a clear, fix-suggesting error:

```
secret("STRIPE_API_KEY") not permitted: missing capability —
  add `require secret("STRIPE_API_KEY")` (or a prefix: `require secret("STRIPE_*")`)
```

### Resolution order (highest priority first)

1. **Process environment** (`X=… synsema run app.syn`, systemd `Environment=`, Docker `-e`) — always wins, so prod overrides without touching the repo.
2. **`.env` file** in the working directory — fills in what the environment doesn't set.
3. **`default`** passed to the builtin — typically your dev value.
4. None of the above → **runtime error** (fail-loud), never a silent `nothing`.

### The `.env` file

Auto-loaded from the working directory at startup, **before** any `require`/`serve`,
so "clone and run" just works.

```
PORT=8080
DATABASE_URL=postgres://localhost/dev
STRIPE_WEBHOOK_SECRET=whsec_dev_xxx       # comment after a space is ignored
QUOTED="value with spaces"
LITERAL='no $interpolation here'
```

- `KEY=VALUE` per line; `#` starts a comment (full line, or after the value if preceded by a space).
- Optional quotes `"…"` / `'…'`. **No variable interpolation** (kept simple and predictable).
- Blank lines ignored; invalid keys → warning, not a crash.
- Override the location: `--env-file <path>` or `SYNSEMA_ENV_FILE=<path>`. Disable: `--no-env-file` (or `SYNSEMA_ENV_FILE=` empty).
- **Commit a `.env.example`** (keys, no values) and keep the real `.env` in `.gitignore`.

> `.env` is the *source*; `env()` vs `secret()` is *how you read* it. The same key can
> be read plain (`env`) or tainted (`secret`).

**The LLM provider config resolves from `.env` too** (same `environ > .env > default` order). Put
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `MINIMAX_API_KEY` / `DEEPSEEK_API_KEY` (and optional
`SYNSEMA_LLM_PROVIDER`/`SYNSEMA_LLM_MODEL`/…) in `.env` and the runtime reaches the provider **without
exporting the key** — it never enters the process environment, and the `.syn` program still can't read
it (it would need `require env/secret`, and even then sees it redacted). See [llm.md](llm.md#provider-setup).

## The `secret` type — LLM-proof by design

A `secret` is an opaque value: you can pass it to the operations that consume it, but
you can never read its plaintext from the language. It is **redacted in every output
surface**, with no flag to turn that off:

| Surface | What you get |
|---|---|
| `print` / console / `show` / `log` | `secret(NAME)` |
| `give` → JSON response body | `"[redacted]"` (+ a warning in the server log) |
| Server-Sent Events (`send`) | `"[redacted]"` |
| 500 error detail (dev mode) | redacted |
| LLM context / `generate … given X` | the model never sees the plaintext |
| blackboard between agents (`share`/`observe`) | redacted on share |
| `text(secret)` / string coercion | `secret(NAME)` |
| `"x" + secret` (concatenation) | stays a `secret` (taint propagates) |
| SQL parametrized write | the **plaintext is written to the DB** (the DB is the trust border) |

Because redaction lives in the value's own `Display`/serialization, an accidental
`print`, log, or `"... " + key` can never leak the plaintext.

### Threat model: prompt injection

Synsema is agent-native, so the threat model includes an LLM with prompt injection
trying to exfiltrate a secret. The `secret` type blocks it in the **data plane**: the
plaintext never enters a model prompt, another agent, a response body, a log, or an
error — no matter what the prompt asks. Combined with capabilities (each agent only
reaches what it declares), there is no route for an LLM to read or emit a secret.

## Using secrets safely (without revealing)

```
require secret("STRIPE_WEBHOOK_SECRET")
require serve(8080)

serve on 8080
    route "POST /webhook/stripe"
        let sig be header_of(request, "stripe-signature")
        when not verify_hmac(read_body(), sig, secret("STRIPE_WEBHOOK_SECRET"))
            give fail(400, "bad signature")
        give ok({"received": true})
```

```
require secret("STRIPE_API_KEY")
require net("api.stripe.com")
let r be fetch("https://api.stripe.com/v1/charges", "POST",
               {"Authorization": bearer(secret("STRIPE_API_KEY"))}, body)
```

| Builtin | Returns |
|---|---|
| `bearer(s)` | a tainted `Bearer <secret>` auth header value |
| `hmac_sha256(data, s)` | the MAC as a hex string (not secret) |
| `verify_hmac(data, sig, s, algo?)` | bool, **constant-time** (HMAC-SHA256/512; SHA-1 rejected) |
| `constant_time_eq(a, b)` | bool, constant-time (accepts a `secret` on either side) |

- A `secret` in an outgoing **header** value (or the result of `bearer()`) is
  materialized to its real value **only at the socket** — never in your program's
  value space. In query params and bodies a `secret` is redacted (fail-closed).
- `verify_hmac` decodes the incoming signature as hex or base64 (covers Stripe,
  GitHub `sha256=…`, Shopify) and compares in constant time.
- `==` on a `secret` is already constant-time; prefer `constant_time_eq`/`verify_hmac`
  for credential checks.

## Sealing a runtime value: `as_secret()`

`secret("NAME")` reads from config. For a sensitive value that **arrives at runtime**
and isn't in `.env` — a user's API key in a request header, a token from another
task/HTTP call — use **`as_secret(value, label?)`** to seal it at the point of entry.
From there it carries the same taint and redaction as any `secret`:

```
-- Multi-tenant / SaaS: the end user brings their own key in a header.
route "POST /proxy"
    let user_key be as_secret(header_of(request, "x-provider-key"), "user_key")
    let r be fetch("https://api.provider.com/v1/...", "POST",
                   {"Authorization": bearer(user_key)}, body)   -- materializes only at the socket
    give {"ok": true}
```

- **No `require` needed.** `as_secret` is a *pure* transformation that only *strengthens*
  security (it seals), so — unlike `secret()`/`reveal()` — it isn't capability-gated. It
  follows `bearer()`, not `secret()`.
- Accepts **text or bytes** (what a secret actually *is*). Other types (number/map/list)
  → a clear error: seal the sensitive **field**, not the whole structure.
- **Idempotent:** `as_secret(x)` where `x` is already a `secret` returns it unchanged
  (no re-nesting, same label).
- `label` is a **non-sensitive** tag shown in redaction (`secret(<label>)`, default
  `sealed`) and is what `reveal` scopes on — **give it a specific label if you plan to
  reveal it** (see below).
- Provenance-agnostic: it doesn't matter whose key it is (yours, a tenant's, a tenant's
  customer's) — you seal what you receive at your edge.

## The one escape hatch: `reveal()`

`reveal(s)` returns the plaintext (a `secret` of bytes reveals as `bytes`). It is
deliberately **loud** and **scoped**:

- requires `require reveal("NAME")` **scoped to the secret's name/label** — it can only
  reveal secrets whose name (`secret("STRIPE_KEY")` → `STRIPE_KEY`) or label
  (`as_secret(v, "user_key")` → `user_key`) is in the granted scope (exact or glob, like
  `secret`/`net`). Revealing anything outside the scope **fails** — even if you point a
  variable at a different secret, the check uses *that* secret's name;
- writes a **persistent, append-only audit entry** (`$SYNSEMA_AUDIT_DIR` or
  `~/.synsema/audit/reveal.log`) for **every attempt — granted or denied**: timestamp,
  result, the secret's name/label, `file:line`, program name — **never the value**;
- if the audit log can't be written, a granted `reveal()` **fails** (no audit, no reveal);
- bare `require reveal` (no scope) still works for backward compat — it permits revealing
  **any** secret — but is **discouraged** and prints a warning. Prefer the scoped form.

```
require reveal("LEGACY_TOKEN")
let plain be reveal(secret("LEGACY_TOKEN"))   -- audited; only LEGACY_TOKEN is revealable here
```

The only way to reveal a given secret is to declare its `require reveal("NAME")` in the
**source** — auditable by reading the `require` lines, and a prompt injection can't add
one (injection is data, not code; capabilities freeze at startup).

Prefer `bearer`/`hmac_sha256`/`verify_hmac`/`constant_time_eq` — they consume the
secret without ever exposing it.

## Dev vs prod — the same code

```
-- The .syn stays dev-clean: `synsema serve app.syn` → :8080, plain HTTP locally.
-- App values resolve from .env in dev and from the environment in prod (no repo edits).
require serve(8080)
serve on 8080
    route "GET /health"
        give {"ok": true}
```

> For the serve **port and TLS** (the deployment *structure*), prefer the CLI flags
> (`--port` / `--domain` / `--tls-auto`) — see [deploy.md](deploy.md). Use
> `env()`/`secret()` for application **values** (DB URL, API keys, webhook secrets),
> not for the serve port.
