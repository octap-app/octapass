# octapass-server

The Octa Pass sync server: OPAQUE sign-up and login, tokens and devices, revision-based sync of encrypted items with batch writes and live WebSocket notifications, quotas, sharing (shared vaults with signed grants and key rotation, families, one-time share links, emergency access), organisations with groups, policies and single sign-on, and account deletion, on SQLite or PostgreSQL. It stores ciphertext only. The API is documented in [`docs/developers/sync-api.md`](../../docs/developers/sync-api.md) and as OpenAPI 3.1 in [`openapi.json`](openapi.json); settings are in [`docs/self-hosting/configuration.md`](../../docs/self-hosting/configuration.md).

```bash
OCTAPASS_DEV_MODE=true cargo run -p octapass-server     # http://127.0.0.1:8080, codes logged
cargo test -p octapass-server -p octapass-api
# The same integration tests on PostgreSQL: each test gets its own database there.
docker run -d --rm --name octapass-pg -e POSTGRES_PASSWORD=pg -p 127.0.0.1:55432:5432 postgres:16-alpine
OCTAPASS_TEST_POSTGRES_URL=postgres://postgres:pg@127.0.0.1:55432/postgres cargo test -p octapass-server --tests
cargo clippy -p octapass-server -p octapass-api --all-targets -- -D warnings
OCTAPASS_UPDATE_OPENAPI=1 cargo test -p octapass-server --test integration api::   # refresh openapi.json
docker build -f apps/server/Dockerfile -t octapass-server .        # from the repository root
```

| Path | What lives there |
|---|---|
| `src/routes/` | HTTP handlers, one file per area, with their OpenAPI annotations |
| `src/db/` | SQL through sqlx's `Any` driver, portable between SQLite and PostgreSQL (`$n` placeholders, TEXT/BIGINT) |
| `src/events.rs`, `src/routes/ws.rs` | Live change notifications |
| `migrations/sqlite/`, `migrations/postgres/` | Schema per backend, applied on startup. Keep them in step, and never edit a released migration. |
| `src/clock.rs` | The clock share-link expiry and emergency access run on; tests move it forward |
| `tests/` | Integration tests that drive the real router with an opaque-ke client; `tests/common/people.rs` makes accounts with real keys, so sharing tests seal, sign and decrypt with `octapass-core` |

Request and response types live in [`crates/octapass-api`](../../crates/octapass-api).
