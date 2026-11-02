# Config, environment & secrets

Synsema is **easy to develop** (one repo, dev defaults, prod by environment) and
**secure by design**: a tainted `secret` type that you *use* but cannot *read* —
LLM-proof, with **zero cost on the hot path**.

## Reading configuration

Define any variable once (in a `.env` file or the process environment) and read it
by name. There are two ways to read, depending on sensitivity:

```synsema
let port be env("PORT", 8080)                 -- plain string config: "8080" when PORT is unset
let key  be secret("STRIPE_API_KEY")          -- opaque, redacted everywhere
let hook be env("WEBHOOK_URL", nothing)       -- nothing when unset (v0.6.45+)
when hook == nothing
    print("no webhook configured")
```

A default is returned as text: a number keeps its text (`env("PORT", 8080)` → `"8080"`), a bool
is Synsema text (`env("X", true)` → `"true"`, v0.6.45+; it used to be `"True"`). **`nothing` as
the default gives `nothing`** when the variable is not defined, for `env` and `secret` alike
(v0.6.45+; before, both gave the text `"None"`, which passed as a valid value — `secret` sent it as
`Bearer None`). A defined variable always wins over the default; without a default, an undefined
variable is an error.

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

If the `require` is there but the HOST ceiling (`--sandbox`/`--cap-set`/embedder `ceiling`)
does not lend it, the error is different on purpose — *declared but above the host ceiling
(--sandbox/--cap-set). The program cannot fix this; the host must widen the ceiling* — so an
agent never "repairs" the code by re-adding a `require` it already has.

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
- `synsema init` writes that `.env.example` for you, and its last section is **your own
  secrets** — the auth features expect keys you name yourself: `JWT_KEY` (`jwt_sign`/
  `jwt_verify`), `CAPTOKEN_ROOT_KEY` (`captoken_mint`/`captoken_verify` — attenuating
  needs no key, which is why a delegated sub-agent never sees it) and
  `AGENT_SIGNING_KEY` (`http_sign`, which also needs `require sign("AGENT_SIGNING_KEY")`).
  The name you pick IS the capability scope; add your own the same way.

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
| `give` → JSON response body | `"[redacted]"` (+ a warning in the server log; outside `serve`, e.g. `evm_rpc` under `run`, v0.6.49+ says `synsema: warning: secret(K) was redacted in a value serialized to JSON`) |
| Server-Sent Events (`send`) | `"[redacted]"` |
| 500 error detail (dev mode) | redacted |
| LLM context / `generate … given X` | the model never sees the plaintext |
| blackboard between agents (`share`/`observe`) | redacted on share |
| `text(secret)` / string coercion | `secret(NAME)` |
| `json_encode` / `jsonl_encode` / `json_for_script` / `csv_encode` | **error** naming where it is (v0.6.46+; it was `"[redacted]"`) |
| a list/map holding a secret in a template hole | **error** (v0.6.46+; it was the text `{k: secret(K)}`) |
| a secret inside a `push_send` payload | **error** (v0.6.49+; it was `[redacted]`): `push_send: the payload["k"] is secret(K), … a push payload goes to the browser, another owner, so a secret cannot travel in it; leave it out of the payload` |
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

```synsema
require secret("STRIPE_WEBHOOK_SECRET")
require serve(8080)

serve on 8080
    route "POST /webhook/stripe"
        when not contains(request.headers, "stripe-signature")
            give fail(400, "missing signature")
        let sig be request.headers["stripe-signature"]   -- header names are lowercased
        when not verify_hmac(read_body(), sig, secret("STRIPE_WEBHOOK_SECRET"))
            give fail(400, "bad signature")
        give ok({"received": true})
```

```synsema
require secret("STRIPE_API_KEY")
require net("api.stripe.com")
let body be {"amount": 2000, "currency": "usd"}
let r be fetch("https://api.stripe.com/v1/charges", {
    "method": "POST",
    "headers": {"Authorization": bearer(secret("STRIPE_API_KEY"))},
    "body": body
})
```

```
-- secret() is NOT Bearer-only: it goes in ANY header. For x-api-key or your own
-- header, pass the raw secret — it's materialized at the socket (redacted in logs).
-- bearer(s) is just sugar for the `Authorization: Bearer <token>` format.
require secret("PROVIDER_KEY")
require net("api.provider.com")
let a be http_get("https://api.provider.com/v1/items",
                  {"x-api-key": secret("PROVIDER_KEY")})          -- custom header
let b be http_get("https://api.provider.com/v1/items",
                  {"x-my-own-header": secret("PROVIDER_KEY")})    -- any name works
```

| Builtin | Returns |
|---|---|
| `basic(user, s)` | a tainted `Basic base64(user:password)` header value (RFC 7617, v0.6.44+): Basic-auth APIs. `user` without `:` |
| `oauth_basic(client_id, s)` | the same for OAuth client credentials: both parts form-encoded first (RFC 6749 §2.3.1), v0.6.44+ |
| `bearer(s)` | a tainted `Bearer <secret>` auth header value. `s`: text or secret (v0.6.44+: `nothing`/bytes/numbers → error, not `Bearer None`) |
| `hmac(data, s, algo?)` | the MAC as **bytes** (not secret; `hex(mac)` to show it). `data`/`s`: text, bytes (raw, v0.6.44+) or secret; other types → error. v0.6.29+ — the old `hmac_sha256` (hex text) is a deprecated alias |
| `verify_hmac(data, sig, s, algo?)` | bool, **constant-time** (HMAC-SHA256/512; SHA-1 rejected). `sig` hex/base64 text or raw bytes; undecodable or missing (`nothing`) → `false`; other type → error |
| `constant_time_eq(a, b)` | bool, constant-time (accepts a `secret` on either side) |

- **Any** outgoing **header** whose value is a `secret` (a raw `secret(...)` /
  `as_secret(...)`, or the result of `bearer()`) is materialized to its real value
  **only at the socket** — never in your program's value space. Credentials are **not
  Bearer-only**: `{"x-api-key": secret("KEY")}` or any custom header works; `bearer(s)`
  is just sugar for the `Authorization: Bearer <token>` format. An **unbound** `secret` in the
  URL, query params, a body or a form is an **error** (v0.6.44+; it used to go out as the text
  `secret(NAME)`), and since v0.6.46 the error gives the line that fixes it —
  `require secret("K") for net("<host of that request>")` — see § bound to a host below.
  Header/query/`bearer` values are text, number, bool or secret — `nothing`, bytes, lists, maps →
  error naming the header (was their printed form, e.g. `Bearer None`); a sealed secret or
  non-UTF-8 bytes secret → error, never `secret(NAME)`.
- **A list/map with a secret inside, in a template hole, is an error** (v0.6.46+): `` `Bearer {creds}` ``
  with `creds = {"k": secret("K")}` → `a secret inside a map cannot go into a text hole (secret(K)
  would travel as its placeholder): take it out on its own (`creds.k`) or use bearer(...)/basic(...)`
  (`inside a list` for a list). Before it gave the plain text `Bearer {k: secret(K)}`. Put the secret
  itself in the hole (`` `Bearer {creds["k"]}` `` is a secret with the real value) or use
  `bearer`/`basic`; a secret alone in a hole is unchanged.
- **`json_encode`/`jsonl_encode`/`json_for_script`/`csv_encode` of a secret are an error** (v0.6.46+),
  also deep inside: `json_encode: the value["auth"]["key"] is secret(K), and a secret is never written
  as text — pass the value to the request itself (in a header; in the body or the URL once it is bound:
  `require secret("K") for net("host")`) and the engine writes it at the socket, or leave it out of what
  you encode` (`jsonl_encode`: `item 0[...]`; `csv_encode: row 1, column "k": secret(K) is never written
  as text — leave it out of the rows`). It used to give `"[redacted]"` — a marker the program could
  send on as the data. **Migrate:** hand the map with the secret to `http_post`/`fetch` directly (bound
  secret) or drop the field. `give` from a route still answers `"[redacted]"` + a server-log warning.
- `as_secret(v)` without a label is NAMED `sealed` (`secret(sealed)`, scope of
  `reveal("sealed")`) — a name, not a sealed secret like `attestation_key()`. Pass a label.
- **As a DB parameter** (`sql`, `mongo_*`, `redis_*`) a secret materializes at the DB edge:
  text as text, a bytes secret as its bytes (BLOB/`bytea`/binary, v0.6.44+; was lossy
  UTF-8); a sealed secret → error, also nested in a list/document.
- **AWS SigV4 / chained HMAC with a stored key:** `hmac(date, "AWS4" + secret("AWS_SECRET_ACCESS_KEY"))`
  — never `bytes(secret)` (does not convert) nor `reveal`.
- `verify_hmac` decodes the incoming signature as hex or base64 (covers Stripe,
  GitHub `sha256=…`, Shopify) and compares in constant time.
- `==` on a `secret` is already constant-time; prefer `constant_time_eq`/`verify_hmac`
  for credential checks.

**A secret never reaches an OS child by accident.** `run`, `proc_spawn` and `run_program` refuse a
`secret()` in the child's `env`, arguments or `stdin`, and nothing runs (`run` since v0.6.53 — before
it passed the text `secret(K)` in `env`/arguments and dropped `stdin` silently):
``run: env "K" is a secret — reveal() it explicitly (audited) if the child really needs the value; nothing ran``.
If the child needs the value, `reveal(secret("K"))` with `require reveal("K")` — audited.

## A secret in the URL, the query or the body: bind it to a host (v0.6.46+)

Some APIs take the key only in the URL (RPC providers, bot and map APIs), in the query, or in the body (OAuth `client_secret_post`). Before v0.6.46 that was an error and the only way out was `reveal()`. Now you **bind** the secret to the hosts it may go to, and then it may travel in the URL, the query, a JSON body at any depth, a form, or a header — only to those hosts:

```synsema
require secret("RPC_KEY") for net("rpc.example.com")
require secret("APP_SECRET") for net("auth.example.com")
require net("rpc.example.com")
require net("auth.example.com")

let k be secret("RPC_KEY")
let a be http_get(`https://rpc.example.com/v2/{k}`)                  -- in the path, as is
let b be http_get("https://rpc.example.com/v2", query = {"key": k})  -- in the query, percent-encoded
let c be http_post("https://rpc.example.com/v2", {"auth": {"key": k}, "op": "status"})  -- JSON body, any depth
let tok be http_post("https://auth.example.com/oauth/token", form = {
    "grant_type": "client_credentials",
    "client_id": "app-1",
    "client_secret": secret("APP_SECRET")})                          -- a form body
```

The engine writes the value at the socket; the program never holds it as text. The rules:

- **The binding is not a grant.** `for net("h")` says where the secret may go; the request still needs `require net("h")` (without it: `Capability not granted: net("h")`).
- **Which hosts.** One or several: `require secret("K") for net("a.example.com"), net("b.example.com")`. A host without a port covers every port; `net("h:8443")` only that port. A subdomain wildcard `*.example.com` covers the subdomains, **not** `example.com` itself — name both if you need both. The host can come from the configuration: `for net(env("RPC_HOST"))` (with `require env("RPC_HOST")`). A name prefix works as in any `secret` scope (`require secret("API_*") for net("h")`). These are load errors: `for net("*")` (`binding a secret to every host is not binding it: name the host it goes to`), `for net("*.com")` (`` `*.com` would cover a whole top-level domain; name the domain``), `for net("a*.example.com")` (`` a `*` may only be the whole first label (`*.example.com`), and nowhere else``), and a secret name with `@` or `|`.
- **Only to those hosts — also in a header.** `http_get: secret(K) is bound to [api.example.com]; this request goes to 127.0.0.1:47100 — it never goes to another host, not even in a header`. A binding with a wildcard does not reach a private address either (as a wildcard `net` grant): ``http_get: `127.0.0.1.nip.io` resolved to 127.0.0.1, a private address; a secret bound to [*.nip.io] goes there only if the binding names it (the host exactly, its address or its CIDR)`` (in `error of r`).
- **Only encrypted.** A bound secret goes over `https://` and `wss://`; `http://` and `ws://` only to `127.0.0.1`, `localhost` or `::1`. Otherwise: `http_get: secret(K) only travels over https; this request to example.com is http://`.
- **The host never comes from a secret.** In a URL that holds a secret, the scheme and the host are written before it. `` `https://{k}.evil/` ``, `` `https://{k}@api.example.com/` `` and `` `https://api.example.com{k}/` `` are errors: `the URL is secret(K) and its host is not written out before the secret; write the scheme and host first (`https://host/…{key}`): the host of a request never comes from a secret`.
- **In the path it goes as is; in `query` and `form` it is encoded.** `` `https://h/v2/{k}` `` puts the value in the URL without percent-encoding it (`url_encode` refuses a secret: `cannot encode a secret (it would leave as text)`). If the key may contain `+`, `/`, `=`, `&` or spaces, pass it with `query = {"key": k}`, which encodes it.
- **Adding two bound secrets** keeps only the hosts both allow; with none in common it is an error: `Cannot add secret(A) and secret(C): the first may only go to [a.example.com, b.example.com], the second only to [c.example.com] — no request can carry both`. `bearer`, `basic` and `oauth_basic` keep the binding of the secret they wrap (and a `"pre-" + k` too).
- **A derived secret is a new, unbound secret.** `hkdf_sha256(k, …)` and `as_secret(v, "S")` give a secret with no binding: it goes only in a header. (The error for them still suggests `require secret("S") for net(...)`, which does not bind a value sealed at runtime — use a header.)
- **What the server echoes is masked.** In the body, the headers and the error of the response — and in a WebSocket text frame and a JSON-RPC error — each secret that went out becomes `[secret K]`, whether it comes back as is, percent-encoded, JSON-escaped or in base64. It is a defense against an accidental echo, **not** against a hostile server (a server can echo it transformed in a way the mask does not know): the guarantee is the binding. A secret shorter than 4 characters is not masked, and the run warns once: `secret(K) is shorter than 4 characters, so its echo in a response is not masked`.
- **The record names the secret, never the value.** With `--audit <file>`, each bound secret that went out writes one entry `{"capability": "secret(\"K\")", "granted": true, "source": "bound-send", "reason": "→ api.example.com", …, "file", "line"}`; `lineage()` lists the secrets of each request in `secrets: ["K"]`. Never the URL nor the value.
- **No redirect carries it.** The native client does not follow redirects: a `301`/`302` comes back as the response, with its `Location` header, and your program decides. (An embedder that implements `http` receives `redirect: "error"` when the request carries a secret: honor it, or the protection is lost on that host.)
- **`synsema check` warns** an unbound secret that goes in the URL, the query, the body or the form of a request, with the line to write: `app.syn:4: warning: secret("K") goes in the url of http_get() but is not bound to a host, and an unbound secret only goes in a header: write `require secret("K") for net("api.example.com")``.
- **The other clients.** `evm_rpc` and the other JSON-RPC builtins, `algod`, `btc_rpc` and `ws_connect` take a bound URL (`` ws_connect(`wss://stream.example.com/v1/{k}`) ``). The **params** of a JSON-RPC call still cannot hold a secret: `evm_rpc: params[0] is a secret — a secret never goes into an RPC request`.

**The host can bind too.** `synsema run --cap-set "secret=K@api.example.com,net=api.example.com,stdout" app.syn` (several hosts: `secret=K@a.example.com|b.example.com`), and the same in a delegated ceiling (`run_program`'s `ceiling`). A program that asks for `K` unbound, or bound to another host, gets the line to write: `secret("K") not permitted: the host binds K to api.example.com; write `require secret("K") for net("api.example.com")``. A program may bind tighter than the host (an unbound `secret=K` in the ceiling accepts a program that binds `K`). A child whose ceiling asks for `K` unbound gets nothing above its parent's binding.

## Sealing a runtime value: `as_secret()`

`secret("NAME")` reads from config. For a sensitive value that **arrives at runtime**
and isn't in `.env` — a user's API key in a request header, a token from another
task/HTTP call — use **`as_secret(value, label?)`** to seal it at the point of entry.
From there it carries the same taint and redaction as any `secret`:

```
-- Multi-tenant / SaaS: the end user brings their own key in a header.
route "POST /proxy"
    when not contains(request.headers, "x-provider-key")
        give fail(400, "missing x-provider-key")
    let user_key be as_secret(request.headers["x-provider-key"], "user_key")
    let r be fetch("https://api.provider.com/v1/...", {"method": "POST",
        "headers": {"Authorization": bearer(user_key)}, "body": body})   -- materializes only at the socket
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

```synsema
require reveal("LEGACY_TOKEN")
let plain be reveal(secret("LEGACY_TOKEN"))   -- audited; only LEGACY_TOKEN is revealable here
```

The only way to reveal a given secret is to declare its `require reveal("NAME")` in the
**source** — auditable by reading the `require` lines, and a prompt injection can't add
one (injection is data, not code; capabilities freeze at startup).

The same audit directory (`$SYNSEMA_AUDIT_DIR` or `~/.synsema/audit`) holds one
append-only log per gated family, all with the same guarantees (every attempt recorded,
never the sensitive value, fail-loud on the granted path): `reveal.log`, `sign.log`
(signatures; a `denied_by=ceiling` entry marks a `SYNSEMA_SIGN_CEILING` cut),
`wallet.log` (custody creation) and `spend.log` (the spend ledger: canonical decimal
amount, unit, quoted reason, `file:line`, program; a `denied_by=ceiling` entry marks a
`SYNSEMA_SPEND_CEILING` cut). A framework that needs time-windowed spend policy reads
`spend.log` with `file.read` over that directory — the runtime itself only keeps the
monotonic per-process totals (`spend_total(unit)`).

Prefer `bearer`/`hmac`/`verify_hmac`/`constant_time_eq` — they consume the
secret without ever exposing it.

## Private keys go in as a `secret`, never as a string

Anything that *signs* — the blockchain key of `sign`, the VAPID private key of `push_send`
(v0.6.15+) — is accepted **only as a `secret`**: `secret("VAPID_PRIVATE_KEY")` from `.env`, or
`as_secret(value, "label")` for a value that arrives at runtime. A plain text key is refused
with the fix in the message ("Never pass a private key as a plain string"); the key value
itself never appears in any error. Keys the engine *generates* (`push_vapid_keys()`,
`mnemonic_generate`) come back already sealed; persisting one is a deliberate
`require reveal("<label>")` + `reveal()` — audited, once.

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
