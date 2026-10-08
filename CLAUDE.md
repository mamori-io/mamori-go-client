# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-package Go client (`package mamori`, module `mamori.io/mamori-go-client`) for the mamori.io enterprise server. It is a port of the TypeScript `mamori-ent-js-sdk` v1.4.9 (tracked in the `Version` const in `client.go`). When behaviour is unclear, the TypeScript SDK is the reference. See README.md "Differences from the TypeScript SDK" for the places where this port deliberately does something different. Requires Go 1.27 (uses `errors.AsType`, `iter.Seq2`).

## Commands

```sh
go test ./...                         # all tests; none need a live server
go test -run TestWebsocketSelect .    # single test
go vet ./...
go build -o bin/ ./examples/...       # example binaries (bin/ is gitignored)
```

Examples need `MAMORI_SERVER`, `MAMORI_USERNAME`, `MAMORI_PASSWORD`. They also read `MAMORI_TIMEOUT` (default 60s) and `MAMORI_DEBUG=1`, which logs HTTP phases. Shared setup is in `examples/internal/setup`.

## Architecture

The package has four layers:

1. **Transport** (`client.go`). `Client.Call`/`CallInto`/`CallText`/`CallStream`/`CallBinary` prefix paths with `/api`. Pass paths such as `"/v1/users"`. `CallV2`/`CallProcedure` use `/v2`. Everything goes through `send`: GET and DELETE params become a jQuery `$.param`-style query string (`query.go`, `EncodeParams`), and other methods send a JSON body. A non-2xx status returns `*APIError`. Sessions use a cookie jar plus a CSRF token scraped from `/` during `Login`. `debug.go` wraps the transport when `WithLogger` is set.
2. **Raw REST API** (`api_*.go`). These are thin `Client` methods, one per endpoint, that return `json.RawMessage`. They mirror the TS `api.*` functions.
3. **Resources** (`<resource>.go`). These are typed structs plus a service. Each service is declared in `services.go` as `type XService service`, a view of the shared `service{client}`. It is wired up in `New()` in `client.go`. **Adding a resource means touching all three places**: declare the service type in `services.go`, add the field to the `Client` struct, and assign it in `New()`.
4. **Websocket** (`websocket.go`). `WSClient` uses `github.com/coder/websocket` (the only dependency). `Select` returns `iter.Seq2[Row, error]`.

Permissions (`permission.go`, `permission_types.go`): each concrete permission embeds `PermissionBase` and implements the `Permission` interface (`Base()`, `GrantOptions()`). `PermissionService.Grant` and `Revoke` take any `Permission`. `PermissionFromRecord` rebuilds typed permissions from server records.

## Conventions

- Every call takes `context.Context` first and returns an `error`. Lookup helpers return `ErrNotFound` instead of nil. Error strings are prefixed with `mamori:`.
- Enums are typed string constants prefixed with their owner type (`SecretProtocolSSH`, `DBPermissionSelect`).
- There are no single-field fluent setters; use exported struct fields. Keep fluent methods only when they contain logic, as `DatasourcePermission.On` does.
- SQL built by the SDK (several resources query through `Client.Select`) must use the helpers in `utils.go`: `sqlQuote`/`SQLEscape` for literals, `checkSQLIdentifier` for unquoted names, and `checkSQLNumber` for numeric ids. URL-escape path segments.
- Loosely-typed server responses are decoded with `looseUnmarshal` (`secret.go`), which tolerates type mismatches between JSON and struct fields.

## Tests

Tests use `newTestClient` (`client_test.go`), which starts an `httptest` server, records every request as `recordedRequest` (method, escaped path, raw query, decoded body), and returns whatever the `respond` callback gives it. Write tests that assert on the recorded requests, including generated SQL. `websocket_test.go` uses an in-process websocket server.
