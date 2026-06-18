# Syntecnia HTTP Server — `serve`

A native HTTP server with **zero dependencies** (built on Python's `http.server`).
Define routes in Syntecnia, the runtime enforces a consistent response contract,
pagination, auth and input validation for you.

## Capability

Serving on a port requires the `serve` capability, scoped to that exact port:

```
require serve(8080)
```

Without it, `serve on 8080` fails with a clear error:
`serve on 8080 is not permitted: missing capability serve(8080). Add `require serve(8080)``.
The scope is the port — `require serve(8080)` does **not** allow `serve on 9090`.

## Basic shape

```
require serve(8080)

serve on 8080
    auth with check_token            -- optional
    route "GET /products"
        give all_products()
    route "POST /products" requires auth
        expect body {name: text, price: number}
        let b be json of request
        give created(b)
```

- `serve on PORT` opens a server block. It starts a background, threaded server
  and returns immediately. The CLI keeps the process alive while servers run.
- `route "METHOD /path"` defines a handler. The body is ordinary Syntecnia.
- Named path params use `:name` → `route "GET /products/:id"`.

## The request

Inside a handler you have:

```
request          -- map with .method .path .body .json .headers .user
json of request  -- parsed JSON body (a map), or nothing
body of request  -- raw body text
headers of request
user of request  -- set after auth (see below)
query            -- query string as a map: /x?page=2 → query.page == "2"
params           -- path params as a map: /products/:id → params.id
```

All `query` and `params` values are text.

## Response contract (enforced by the runtime, on the BODY you `give`)

| You `give`        | Response body                                                        |
|-------------------|----------------------------------------------------------------------|
| a **map**         | the object as-is                                                     |
| a **list**        | `{"items": [...], "count": <page>, "total": <real>, "cursor": <next or null>}` |

Helpers set the HTTP status:

```
ok(x)             -- 200, body shaped per the table above
created(x)        -- 201
not_found(x)      -- 404 → {"error": x, "status": 404}
fail(code, msg)   -- {"error": msg, "status": code}
```

Errors never crash the server:

```
expect failure         → 400  {"error": "...", "status": 400, "field": "..."}
uncaught error / 1/0   → 500  {"error": "...", "status": 500}
unknown route          → 404
```

## Pagination

Collections are **never** returned unbounded.

- Default `limit` is 100 (max 1000).
- `?limit=N` sets the page size.
- `?cursor=N` (or `?offset=N`) sets where the page starts.
- `total` is always the real total; `cursor` is the next offset, or `null` on the last page.

```
GET /products?limit=2          → {"items":[...2...], "count":2, "total":57, "cursor":2}
GET /products?limit=2&cursor=2 → {"items":[...2...], "count":2, "total":57, "cursor":4}
```

## Auth (incoming)

```
serve on 8080
    auth with check_token
    route "GET /me" requires auth
        give {"name": name of (user of request)}
```

For a route marked `requires auth`, the runtime:
1. extracts the bearer token from `Authorization: Bearer <token>`,
2. calls the `auth with` task with that token,
3. if it returns `nothing` → responds **401**,
4. otherwise the returned value is placed in `request.user`.

```
task check_token(token)
    when token == "secret"
        give {"name": "alice"}
    give nothing
```

## Input validation

```
route "POST /users"
    expect body {name: text, age: number}
    ...
```

`expect body {field: type, ...}` validates the request's JSON body. A missing
field or a type mismatch → **400** with the offending `field` named. Types:
`text`, `number`, `bool`, `list`, `map`.

## Isolation

Every request runs in its own isolated interpreter and scope (its own variables,
logs and trace) — just like a spawned agent. There is **no shared mutable state**
between requests except the blackboard (`share`/`observe`) and the database
(`sql`/`sql_exec`). Always use parameterized `sql(..., [params])` — never string
concatenation — so path/query/body values can't inject SQL.

## Full example

```
require serve(8080)
require db("./store.db")

db_open("./store.db")
sql_exec("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price NUMBER)")

task check_token(token)
    when token == "admin-key"
        give {"role": "admin"}
    give nothing

serve on 8080
    auth with check_token

    route "GET /products"
        give sql("SELECT id, name, price FROM products")

    route "GET /products/:id"
        let rows be sql("SELECT id, name, price FROM products WHERE id = ?", [params.id])
        when length(rows) == 0
            give not_found("product not found")
        give rows[0]

    route "POST /products" requires auth
        expect body {name: text, price: number}
        let b be json of request
        sql_exec("INSERT INTO products (name, price) VALUES (?, ?)", [name of b, price of b])
        give created({"created": true})
```

Run it:

```bash
syntecnia run store.syn      # stays alive while the server runs; Ctrl+C to stop
```
