# octapass-push-relay

The Octa Pass push relay (plan 04, "Push relay"): holds the APNs and FCM credentials and passes content-free wakeups from Octa Pass servers on to phones. A push is a token and one word, `sync` or `alert`; the relay stores no tokens, only the servers (installations) allowed to send. Setup and what it can see are in [`docs/self-hosting/push-relay.md`](../../docs/self-hosting/push-relay.md).

```bash
cargo test -p octapass-push-relay
```

| Module | Does |
|---|---|
| `api` | `POST /v1/installations`, `POST /v1/push`, `GET /healthz` |
| `apns` | Apple's HTTP/2 API with an ES256 provider token |
| `fcm` | Firebase Cloud Messaging HTTP v1 with a service account's OAuth token |
| `jwt` | ES256 and RS256 compact tokens, signed with ring |
| `db` | Installations, on SQLite or PostgreSQL |
| `limits` | Token buckets per installation and per address |

The tests run against fake Apple and Google endpoints on local ports. `tests/fixtures/test-rsa.pem` is a key for tests only.
