---
title: Configuration
description: Configure a self-hosted Octa Pass server with OCTAPASS_* environment variables, covering URLs, data directory, database, email, signups, CORS, security keys and the admin CLI.
status: in-progress
sidebar:
  order: 4
---

:::note[In progress]
Every setting on this page works today, with SQLite or PostgreSQL, except those under [Planned](#planned). Option names may still change before the first release.
:::

The server reads `OCTAPASS_*` environment variables.

## Core settings

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_PUBLIC_URL` | `http://<bind address>` | The public URL of your server. Used in emails; when it starts with `https://` the server also sends HSTS. |
| `OCTAPASS_BIND` | `127.0.0.1:8080` | Address and port to listen on. The Docker image sets `0.0.0.0:8080`. |
| `OCTAPASS_DATA_DIR` | `./data` | Holds the database, the server's secrets and, unless you use S3, attachments. The Docker image uses `/data`. |
| `OCTAPASS_DATABASE_URL` | `sqlite://<data dir>/octapass.db` | SQLite, or PostgreSQL 16+ with `postgres://user:password@host:5432/database`. The schema is created and upgraded on startup. |
| `OCTAPASS_MAX_ITEMS` | `50000` | Items each account may store in the vaults it owns, trash included. |
| `OCTAPASS_MAX_ITEM_BYTES` | `1073741824` (1 GiB) | Item ciphertext each account may store, as sent (base64url). |
| `OCTAPASS_FAMILY_MAX_MEMBERS` | `6` | Members plus pending invites a family may have, the organiser included (2 to 100). |
| `OCTAPASS_WEB_ORIGINS` | `http://localhost:5173` | Comma-separated origins allowed to call the API from a browser (the web vault). |
| `OCTAPASS_WEBAUTHN_RP_ID` | the host of the first web origin | The WebAuthn relying party id that security keys for [two-step sign-in](/docs/features/two-step-sign-in/) are registered for: the web vault's host, or a parent domain of it. Changing it later makes existing security keys stop working (authenticator apps and recovery codes keep working). |
| `OCTAPASS_TRUST_PROXY` | `false` | Set to `true` behind a reverse proxy, so rate limits use the last `X-Forwarded-For` address. Leave it off otherwise, or clients can fake their address. |
| `OCTAPASS_WEB_DIR` | unset; `/web` in the Docker image | Serves the built web vault from this folder on the server's own origin. Paths outside `/v1` that match no file get `index.html`. Its pages get a CSP allowing only this origin plus `wasm-unsafe-eval`. |
| `OCTAPASS_LOG` | `info` | Log filter, for example `debug` or `octapass_server=debug`. Logs never contain request bodies, tokens or query strings. |

## Attachments

Users' [attachments](/docs/features/attachments/) are encrypted on their devices; the server stores ciphertext only. By default the files go in the `attachments` folder of the data directory. Set `OCTAPASS_S3_BUCKET` to keep them in S3-compatible object storage instead (AWS S3, MinIO, Garage, Backblaze B2, Wasabi, Hetzner and others).

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_MAX_ATTACHMENT_BYTES` | `1073741824` (1 GiB) | Attachment storage per account, counted over the vaults it owns (trash included), as stored. |
| `OCTAPASS_MAX_FILE_BYTES` | `104857600` (100 MiB) | The largest single file, as stored. Encryption adds 52 bytes plus 16 per 64 KiB. |
| `OCTAPASS_S3_BUCKET` | unset | Turns on object storage. |
| `OCTAPASS_S3_ENDPOINT` | `https://s3.<region>.amazonaws.com` | Your provider's endpoint, for example `https://minio.example.com:9000`. |
| `OCTAPASS_S3_REGION` | `us-east-1` | The bucket's region, as your provider names it. |
| `OCTAPASS_S3_ACCESS_KEY_ID`, `OCTAPASS_S3_SECRET_ACCESS_KEY` | required with a bucket | Credentials that may put, get and delete objects in the bucket, and check it exists. |
| `OCTAPASS_S3_PATH_STYLE` | `true` when `OCTAPASS_S3_ENDPOINT` is set, otherwise `false` | `https://endpoint/bucket/key` instead of `https://bucket.endpoint/key`. Most self-hosted servers need path style. |

Requests are signed with AWS Signature Version 4. Object names are random and say nothing about accounts or items. Uploads go through a temporary file in `<data dir>/uploads`, so there must be room there for the largest file being uploaded. When files are deleted (by users, with their items after 30 days in the trash, or with an account), the server deletes them from storage straight away and retries with backoff, up to once a day, while the storage is unreachable. `/readyz` fails while the storage can't be reached.

## Email and signups

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_SMTP_URL` | unset | `smtp://` or `smtps://user:pass@host:port` for outgoing email. Without it (and without `OCTAPASS_EMAIL_TO_LOG` or dev mode) nobody can sign up, because sign-ups need a verified email. |
| `OCTAPASS_SMTP_FROM` | `Octa Pass <noreply@<public host>>` | The sender address. |
| `OCTAPASS_SIGNUPS` | `open` | `open`, `invite` (only emails added with `admin invite` or `OCTAPASS_INVITES`) or `closed`. |
| `OCTAPASS_INVITES` | unset | Comma-separated emails invited at every start, while they have no account. |
| `OCTAPASS_EMAIL_TO_LOG` | `false` | Writes each email's recipient and subject to the log, where the sign-up code is. For servers without SMTP. Unlike dev mode, codes are never returned to clients. |
| `OCTAPASS_DEV_MODE` | `false` | Logs emails and returns verification codes in the API response. **Never enable it on a server other people use.** |
| `OCTAPASS_RATE_LIMITS` | `on` | `off` turns off the rate limits (sign-in, lookups, share links, emergency contacts, icons), for local test suites that sign in many times from one address. Only accepted together with `OCTAPASS_DEV_MODE=true`. |

## Masked email relay

Off unless both are set; see [the masked email relay](/docs/self-hosting/relay/).

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_RELAY_API_URL` | unset | The relay's internal API. Unset, `/v1/masked-email` answers 404. |
| `OCTAPASS_RELAY_API_TOKEN` | required with the URL | The token the relay expects. |

## Push sync

Off by default. With it on, your server wakes your users' iPhones and Android phones through a [push relay](/docs/self-hosting/push-relay/) when something they can see changes, so they sync in the background instead of waiting to be opened. Apple and Google only deliver pushes from the app's publisher, which is why a relay sits between your server and them. A push says only `sync` or `alert`: no account, email, vault, item or name.

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_PUSH_RELAY` | `false` | `true` turns push sync on. Your server registers with the relay on its own the first time, keeps the installation in its database, and from then on sends the relay each woken phone's push token and one word. |
| `OCTAPASS_PUSH_RELAY_URL` | `https://push.octap.app` | The relay to use. The Octa Pass relay isn't running yet, so for now this has to be one you run. Only allowed with `OCTAPASS_PUSH_RELAY=true`. |

`GET /v1/server-info` reports `pushRelay: true` once the server is registered, and the apps then hand it their push tokens. A server that can't reach the relay keeps working: phones sync when they're opened and while they're open, as without push. If the relay loses track of your server, it registers again at the next maintenance round, every 5 minutes. If the relay's operator revokes it, your server stops sending pushes until it restarts.

## Key log witnesses

Off unless set. Independent [witnesses](/docs/self-hosting/key-log-witnesses/) cosign your server's [key log](/docs/security/post-quantum-and-key-log/#the-key-log), so it can't show different people different logs. `octapass-server admin key-log` prints the verifier key their operators need.

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_KEY_LOG_WITNESSES` | unset | Witnesses, separated by commas or newlines: each a submission URL and the witness's verifier key, separated by a space. At most 16. |
| `OCTAPASS_KEY_LOG_WITNESS_QUORUM` | a majority | How many witnesses must cosign. |
| `OCTAPASS_KEY_LOG_WITNESS_INTERVAL` | `600` | Seconds between checkpoints sent to the witnesses (10 to 86400). |

## Website icons

Apps show each item's [website icon](/docs/features/website-icons/) by asking your server (`GET /v1/icons/{domain}`), which fetches it from the website itself and keeps it in the `icons` folder of the data directory for a week. Requests carry no account or token. The server only connects to public internet addresses, so a website can't point it at your own network. It needs outgoing HTTPS (and HTTP) access to the internet.

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_SSO_PRIVATE_NETWORK` | `off` | `on` lets the server reach an [identity provider](/docs/features/single-sign-on/) on a private address. Off, it reaches public addresses only. HTTPS is required either way. |
| `OCTAPASS_ICONS` | `on` | The [website icon](/docs/features/website-icons/) proxy. `off` stops the server fetching icons: apps then show initials and stop asking. Turn it off if your server can't reach the internet, or you don't want it to fetch websites. |

## Email breach alerts

[Email breach alerts](/docs/security/breach-checks/#email-breach-alerts-opt-in) are off unless you set a Have I Been Pwned API key, which you get from HIBP. Without one, users don't see the switch and the endpoint answers 404. With one, each user still has to turn alerts on, and their addresses then pass through your server on the way to HIBP.

| Variable | Default | Description |
|---|---|---|
| `OCTAPASS_HIBP_API_KEY` | unset | Your HIBP API key. Setting it makes the feature available to your users. It's a secret: pass it like your database password. |
| `OCTAPASS_HIBP_REQUESTS_PER_MINUTE` | `10` | What your HIBP plan allows, for the whole server. Requests beyond it wait up to 15 seconds, then get a `429`. |

## The data directory

On first start the server creates two secret files in the data directory, readable only by the server's user:

| File | Purpose |
|---|---|
| `opaque-server-setup.bin` | The OPAQUE server key. If it's lost, **nobody can sign in again**. |
| `server-secret.bin` | Keys the fake sign-in salts for unknown emails and the verification code hashes. |

Back up the whole data directory, not just the database. Everything in it except these two files is ciphertext or metadata. See [backups](/docs/self-hosting/backups/).

The `icons` folder only caches public website icons. Its file names are keyed with the server secret, so it isn't a readable list of websites, but the icons themselves show which sites your users' vaults have; keep it as private as the rest. You can delete it at any time, and it needn't be backed up.

With SQLite, deleted rows are overwritten in the database file (`secure_delete`) and the write-ahead log is emptied after each account deletion, so a deleted account can't be recovered from the data directory. PostgreSQL reuses the space of deleted rows through autovacuum, but old row versions can stay on disk and in WAL archives until then; keep its data directory and archives as private as the backups. Deleted accounts disappear from backups only as you rotate them. The hosted service keeps backups for at most 30 days; do the same if you make your users that promise.

## Admin CLI

Run these with the same environment as the server (in Docker: `docker exec octapass octapass-server admin …`).

```bash
octapass-server admin invite alice@example.com          # allow a sign-up when OCTAPASS_SIGNUPS=invite
octapass-server admin delete-account alice@example.com  # delete an account and everything in it
octapass-server admin reset-two-step alice@example.com  # turn off two-step sign-in for someone who lost every method
octapass-server admin backup /backups                   # a backup of the database, secrets and attachments (SQLite)
octapass-server admin restore /backups/octapass-…       # put a backup in place (stop the server first)
octapass-server admin key-log                           # the key log's verifier key, for witnesses, and how witnessing stands
octapass-server admin key-log witness                   # send a checkpoint to the witnesses now and report
octapass-server healthcheck                             # exit 0 when the server answers /healthz
octapass-server openapi                                 # print the API as OpenAPI 3.1
```

Backups and restore are described in [backups](/docs/self-hosting/backups/).

`admin delete-account` does exactly what in-app account deletion does, without asking for the password, and sends the user the confirmation email. It can't be undone.

`admin reset-two-step` removes the account's authenticator app, security keys and recovery codes, records it in the user's security log and emails them. Use it only once you're sure who's asking: it leaves the master password and Secret Key as the only protection for new sign-ins.

## Limits

These are fixed for now:

| Limit | Value |
|---|---|
| Request body | 1 MiB, 16 MiB for `POST /v1/batch` |
| Item overview / details | 64 KiB / 512 KiB of ciphertext |
| Batch | 1,000 operations |
| Sync page | About 1,000 items or 8 MiB |
| Auth rate limits | See [rate limits](/docs/developers/sync-api/#rate-limits) |
| Sign-up codes per email | 10 sent and 20 wrong guesses per UTC day |
| Request timeout | 30 seconds; attachment uploads and downloads 1 hour, and an upload that sends nothing for 1 minute is stopped |
| WebSocket | Pinged every 30 seconds; closed when its access token expires |

## Planned

| Setting | Purpose |
|---|---|
| `octapass.toml` | The same settings as a file |
| Email domain allowlist | Only allow sign-ups from given domains |
| Pwned Passwords mode | Proxy through your server (default) or let clients call HIBP directly |
| Redis/Valkey URL | Shared rate limiting across several instances |
| Metrics | Prometheus `/metrics` on a separate port, aggregate only |
| More admin commands | `disable-signups`, `quota` |
