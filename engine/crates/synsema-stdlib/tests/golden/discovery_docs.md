# Bookshop API — API reference

> Sell books to agents and humans

Version 1.4.0 · base URL https://books.example · machine-readable: /openapi.json · /llms.txt · /sitemap.xml

Authentication (protected operations): `Authorization: Bearer <token>`, a session cookie, or an HTTP Message Signature (RFC 9421). Details: /.well-known/synsema-auth

## GET /

- rate limit: 100 per 60s

Response: 200 negotiated by Accept: text/html, text/markdown or application/json

## GET /books/{id}

one book

- rate limit: 100 per 60s

Path parameters: `id`

Response: 200 application/json

## GET /events

- rate limit: 100 per 60s
- streams server-sent events

Response: 200 text/event-stream

## GET /go

- rate limit: 100 per 60s

Response: 302 redirect

## GET /health

- rate limit: unlimited

Response: 200 text/html

## POST /orders

place an order

- requires auth
- rate limit: 5 per 60s
- capabilities: [llm, net, net:api.stripe.com]

Request body (application/json, every field required):

- `book`: text
- `qty`: number
- `gift`: bool

Response: 200 application/json

## GET /upstream/{path}

- rate limit: 100 per 60s
- reverse proxy

Path parameters: `path`

Response: 200 application/json

## GET /v1/shop

- rate limit: 100 per 60s

Response: 200 text/html

## GET /v1/shop/{id}

- rate limit: 100 per 60s
- capabilities: [db, db:./shop.db]

Path parameters: `id`

Response: 200 application/json

## POST /v1/shop/buy

- rate limit: 100 per 60s

Request body (application/json, every field required):

- `item`: text

Response: 200 application/json
