# octapass-relay

The Octa Pass masked email relay (plan 06, Phase B): forwards mail to aliases inside the SMTP transaction, without storing it. It's a service of its own, off unless configured, and has no access to vault data. Setup and DNS are in [`docs/self-hosting/relay.md`](../../docs/self-hosting/relay.md).

```bash
cargo test -p octapass-relay
cd apps/relay/fuzz && cargo +nightly fuzz run smtp_command   # also: dsn, data, headers
```

| Module | Does |
|---|---|
| `smtp` | The inbound server: one task per connection, strict limits, command parser |
| `pipeline` | Deciding a recipient at RCPT, and what happens to the message after DATA |
| `rewrite` | Header rewriting for each direction |
| `auth` | SPF, DKIM, DMARC, ARC through `mail-auth` |
| `srs` | Signed return paths |
| `dsn` | Reading delivery reports and abuse reports |
| `db`, `keys` | The database, sealed addresses, keyed lookups |
| `api` | The internal API the vault server calls |

The keys in `tests/fixtures` are for tests only.
