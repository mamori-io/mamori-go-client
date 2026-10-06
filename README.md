# mamori Go client

An idiomatic Go client for the [mamori.io](https://mamori.io) enterprise
server. It is a port of the TypeScript
[mamori-ent-js-sdk](https://github.com/mamori-io/mamori-ent-js-sdk) (v1.4.9).

```sh
go get mamori.io/mamori-go-client
```

```go
import mamori "mamori.io/mamori-go-client"

ctx := context.Background()
c, err := mamori.New("https://mamori.example.com", mamori.WithInsecureSkipVerify())
if err != nil { ... }
if _, err := c.Login(ctx, "alice", "secret"); err != nil { ... }
defer c.Logout(ctx)

rows, err := c.Select(ctx, "select * from SYS.USERS")          // REST SQL
secret, err := c.Secrets.GetByName(ctx, "db-root")             // typed service
err = c.Secrets.GrantTo(ctx, "db-root", "bob")
_, err = c.Permissions.Grant(ctx, mamori.NewDatasourcePermission("bob",
	mamori.DBPermissionSelect).On("pg", "*", "*", "*"))
```

See [`examples/`](examples) for runnable programs. They read `MAMORI_SERVER`,
`MAMORI_USERNAME` and `MAMORI_PASSWORD`.

## Layout

The library is one package with three layers.

| Layer | TypeScript | Go |
|---|---|---|
| Transport | `MamoriService.callAPI`, `callAPIText`, `callAPIStream`, `callAPIBinary`, `callV2API`, `call` | `Client.Call`, `CallInto`, `CallText`, `CallStream`, `CallBinary`, `CallV2`, `CallProcedure` |
| Raw REST API | `api.create_secret(...)`, `api.users_search(...)`, ... | `c.CreateSecret(ctx, ...)`, `c.UsersSearch(ctx, ...)`, ... returning `json.RawMessage` |
| Resources | `io_secret.Secret`, `io_user.User`, `io_permission.*`, ... | structs plus a service per resource: `c.Secrets`, `c.Users`, `c.Permissions`, `c.Datasources`, ... |
| Websocket | `MamoriWebsocketClient` | `WSClient` (`DialWebsocket`, `Client.WebsocketLogin`); `Select` returns an `iter.Seq2[Row, error]` |

## Differences from the TypeScript SDK

- **Context and errors.** Every call takes a `context.Context` and returns an
  `error`. Non-2xx responses are `*APIError`, and `mamori.StatusCode(err)`
  gives the HTTP status. The `noThrow`/`ignoreError` helpers and the
  `{errors: ..., result: ...}` return objects are gone.
- **Lookups.** Helpers that returned `null` for a missing object return
  `ErrNotFound` instead.
- **No fluent setters.** `withX` setters that only set one field are replaced
  by exported struct fields. Fluent methods that carry real logic are kept,
  such as `DatasourcePermission.On` and `HTTPResource.SetURL`.
- **Permissions.** Instead of `new SecretPermission().name(n).grantee(g).grant(api)`,
  call `c.Permissions.Grant(ctx, mamori.NewSecretPermission(n, g))`. Validity
  goes in the `Validity` field, using `mamori.ValidFor(1, mamori.Hours)` and
  similar. `PermissionFromRecord` replaces `Permissions.factory`.
- **Enums.** Enums are typed string constants, prefixed with their owner, for
  example `SecretProtocolSSH`, `DBPermissionSelect` and
  `MamoriPrivilegeCreateUser`.
- **Sessions.** Cookies are handled by an `http.CookieJar`. `NewSession()`
  replaces `createClient()`. The `authorization` event is replaced by
  `WithAuthorizationHook`.
- **Not ported.** The opt-in response cache (used only for timezones) and the
  `Eventable` base class are not ported.
- **Escaping.** SQL built by the SDK escapes quoted values, and numeric ids are
  validated. Some path segments that TypeScript concatenated raw are now
  URL-escaped. For ordinary names the result is the same.
- **TypeScript bugs fixed.** A few TypeScript bugs are fixed:
  - VNC remote desktop create/update.
  - `Role.revokeFrom` argument order.
  - The shared `pushtotp`/`pushmobile` config object in `setServerDomain`.
  - Alert action descriptions.

## Testing

```sh
go test ./...
```

The unit tests run each request builder against an `httptest` server and
check the method, path, query, body and generated SQL. The websocket client is
tested against an in-process websocket server. None of the tests need a live
mamori server.
