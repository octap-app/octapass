# 04 — Sync server

The server is the same binary for the free hosted service and for self-hosters.

## Responsibilities

- Account registration and login (OPAQUE), sessions, devices, account 2FA
- Store and sync encrypted vaults, items and attachments
- Route shared vault keys between accounts
- Send transactional email (verification codes, new-device alerts, two-step sign-in changes, emergency access notices). Each email is plain text plus a branded HTML part (`apps/server/src/mail.rs`): no remote images, tracking or links, user-chosen names escaped, the logo attached inline
- Optional proxies: Pwned Passwords range API, HIBP email breach API, website icons (so clients don't leak browsing to icon services)
- Rate limiting, abuse prevention, quotas

The server **never** decrypts anything, and it has no code path that could.

## Stack

| Component | Choice |
|---|---|
| Language/framework | Rust, `axum`, `tokio`, `tower` middleware |
| Database | PostgreSQL 16+ (hosted, larger self-hosts) or SQLite (small self-hosts), via `sqlx` with per-backend migrations |
| Attachments | S3-compatible object storage (hosted: any S3 provider; self-host: MinIO/Garage or the local filesystem) |
| Real-time | WebSocket at `/v1/ws` sending "vault changed" notifications only |
| Email | SMTP (any provider); templates in `apps/server/templates`, localised |
| Rate limiting | In-process token buckets; Redis/Valkey optional for multi-instance |
| Config | Env vars or `octapass.toml` |
| Packaging | One static binary + one OCI image (`ghcr.io/octapass/server`), multi-arch (amd64, arm64) |

## Data model (simplified)

```
accounts(id, email, email_verified_at, kdf_params, account_salt, opaque_record,
         wrapped_ask, public_enc_key, public_sign_key, wrapped_private_keys,
         recovery_wrapped_ask, quota_bytes, created_at)
two_step(account_id, totp_secret_sealed, totp_last_step, enabled_at)        -- account 2FA
security_keys(id, account_id, credential_id, algorithm, public_key, sign_count, name, ...)
recovery_codes(account_id, code_hash) / trusted_devices(token_hash, account_id, device_id, expires_at)
devices(id, account_id, name, device_public_key, last_seen_at, revoked_at)
sessions(id, device_id, refresh_token_hash, expires_at)
vaults(id, type[personal|shared|family], revision, created_by, created_at)
vault_members(vault_id, account_id, role[read|write|manage], wrapped_vault_key, signed_by, added_at)
items(id, vault_id, revision, encrypted_item_key, overview_ct, details_ct, deleted_at, updated_at)
item_history(item_id, revision, overview_ct, details_ct, created_at)      -- last 10 revisions
attachments(id, item_id, size_bytes, object_key, encrypted_metadata, created_at)
share_links(id, ciphertext, expires_at, max_views, views, created_by)     -- key lives in URL fragment
emergency_contacts(grantor_id, grantee_id, wait_days, sealed_ask, status, requested_at)
families(id, organiser_id) / family_members(family_id, account_id)
audit_events(account_id, type, ip_hash, created_at)                        -- for the user's own security log
```

## Sync protocol

- Every vault has a monotonically increasing `revision`. Every item stores the vault revision at its last change.
- **Pull:** `GET /v1/sync?since=<map of vault_id → revision>` returns changed items, deletions (tombstones kept 90 days), membership changes and new wrapped vault keys.
- **Push:** `PUT /v1/vaults/{vid}/items/{iid}` with `If-Match: <item revision>`. A mismatch returns `409` with the current server version.
- **Conflicts:** the client merges per field when it can (edits to different fields). When it can't, the server version wins and the local version is saved as a **conflict copy** in the same vault, with a banner in the UI. Data is never silently dropped.
- **Batching:** `POST /v1/batch` for imports (up to 1,000 items per request, transactional per vault).
- **Signed manifests (P1):** after each push, the client signs `(vault_id, revision, hash of item revision list)` with its account Ed25519 key. Other clients verify this, so the server can't hide or roll back items.

## API conventions

- JSON over HTTPS, `/v1` prefix, OpenAPI 3.1 spec generated from `octapass-api` types (via `utoipa`) and published in the docs.
- Errors: `application/problem+json` (RFC 9457) with stable `type` URIs.
- Pagination: cursor-based.
- Idempotency keys on create endpoints.
- CORS: only the web vault origin and the extension origins.
- Security headers on everything: HSTS preload, strict CSP, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, COOP/COEP on the web vault.

## Self-hosting

```bash
docker run -d --name octapass \
  -p 8080:8080 \
  -v octapass-data:/data \
  -e OCTAPASS_PUBLIC_URL=https://vault.example.com \
  -e OCTAPASS_SMTP_URL=smtps://user:pass@smtp.example.com:465 \
  ghcr.io/octapass/server:latest
```

- SQLite (`OCTAPASS_DATABASE_URL=sqlite:///data/octapass.db`) + local attachments by default. Set `OCTAPASS_DATABASE_URL=postgres://…` and `OCTAPASS_S3_*` to scale.
- The image also serves the web vault (static files), so one container is a complete deployment.
- `docker compose` example with Postgres + Caddy (automatic TLS) in the docs.
- Admin CLI: `octapass-server admin {invite,disable-signups,quota,backup,restore}`.
- Backups: `octapass-server backup` writes a consistent snapshot. Because everything is ciphertext, backups can be stored anywhere.
- Signups can be open, invite-only or disabled. An allowlist of email domains is supported.
- Clients choose a server at sign-in ("Octa Pass Cloud" or "Self-hosted: https://…").

## Hosted service specifics

- Region: EU by default (see plan 00 open questions). Data residency is stated on the website.
- Free tier: unlimited items and devices, 1 GB of attachments (once attachments ship in phase 5), families up to 6 (see plan 10 for cost).
- Abuse: proof-of-work on signup, disposable-email blocklist, per-IP signup limits, attachment scanning **impossible** (encrypted), so quotas are the main control.
- Status page and a public uptime history.

## Account deletion

`DELETE /v1/account` requires a fresh re-authentication (OPAQUE with the master password, single-use 5-minute token) and the typed account email. In one transaction the server deletes the account and everything linked to it: keys, devices, tokens, vaults, items, history, tombstones, attachments (object storage deletes are queued and retried), and shared-vault memberships. Nothing identifying is kept. Other devices get `401 account-deleted` and wipe their local data. Encrypted backups age out within 30 days. Self-hosted admins can also run `octapass-server admin delete-account <email>`. The exact steps are in plan 11.

## Push relay (for self-hosted servers)

**Built (2026-11-08), not run against Apple or Google.** See History.

- A small service run by the Octa Pass project (`apps/push-relay`, `octapass-push-relay`) that holds the APNs and FCM credentials.
- A self-hosted server opts in with `OCTAPASS_PUSH_RELAY=true` (and `OCTAPASS_PUSH_RELAY_URL` for another relay), registers once and gets an installation ID and key, kept in its database.
- On a change it sends `{installation_id, [{platform, device_push_token, sandbox, kind}]}`, where `kind` is `sync` or `alert`. **No vault IDs, item data, names or account emails.** Tokens are the ones Apple and Google give each app install.
- Rate-limited per installation. Abuse leads to the installation key being revoked.
- The hosted service runs the same relay and points its server at it.

## Operations

- Health endpoints: `/healthz` (liveness), `/readyz` (DB + storage reachable).
- Metrics: Prometheus `/metrics` on a separate port; aggregate only.
- Migrations run on startup with an advisory lock; rollback scripts are kept for one minor version.
- Zero-downtime deploys behind a load balancer. The WebSocket reconnects with jitter.

## History
- 2026-10-24 (production release, branch m17-release): the server can serve the built web vault on its own origin (`OCTAPASS_WEB_DIR`; the Docker image builds it in with `VITE_SERVER_URL=same-origin`). Pages outside `/v1` get their own headers: CSP `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self' wss://<host>; worker-src 'self'; …; frame-ancestors 'none'`, COOP `same-origin`, COEP `require-corp`, CORP `same-origin`, `no-cache` for pages and `immutable` for hashed `assets/`; unknown page paths get `index.html`, missing files 404. Also `OCTAPASS_INVITES` (invited at start while they have no account), `OCTAPASS_EMAIL_TO_LOG` (email subjects to the log for SMTP-less servers; codes still never in API responses outside dev mode), scheduled SQLite backups (`OCTAPASS_BACKUP_DIR`, `OCTAPASS_BACKUP_EVERY_HOURS`, `OCTAPASS_BACKUP_KEEP`) with `admin backup`/`admin restore`, and `octapass-server healthcheck` for the distroless image. Deployment decisions in plan 10 History.
- 2026-10-24 (website icons, branch m13-site-icons): the optional icon proxy above, built as `GET /v1/icons/{domain}` (`apps/server/src/icons/`). Unauthenticated and token-free, so a request can't be tied to an account; per-IP bucket `icons_per_ip` (200, then 4/s); `OCTAPASS_ICONS=off` answers `404 icons-off` so clients stop asking. Fetches from the site only (home page `<link rel=icon|apple-touch-icon>`, best size near 64–128 px, then `/apple-touch-icon.png`, `/favicon.ico`), never an icon service. SSRF: its own resolver keeps only public unicast addresses (no private, loopback, link-local, multicast, CGNAT, documentation, benchmarking, reserved, ULA, or IPv4 hidden in mapped/6to4 addresses), connects to exactly those, default ports only, no proxy, redirects by hand (max 3, each re-checked); 3 s connect, 5 s per request, 15 s per site; 512 KB of HTML, 256 KB per icon after decompression. Every icon is sniffed, decoded under limits (`image` crate: 2048 px, 32 MB) and re-encoded as a ≤128 px PNG; SVG is rasterised with `resvg` (no external images or fonts, svgz refused), so clients never get site bytes. Cache: files in `<data dir>/icons` (no migration), 7 days for icons and 1 day for misses, names HMAC-keyed with a key derived from the server secret; purged by maintenance. One fetch per domain at a time, 8 domains at once. Privacy trade-off recorded in plan 03 History; API in `docs/developers/sync-api.md`.
- 2026-10-24 (account 2FA, branch m7-account-2fa): two-step sign-in on the server, migration `0006_two_step` (0005 is reserved for another branch). `login/finish` answers `401 second-factor-required` with a `secondFactor` challenge once OPAQUE succeeds; `POST /v1/auth/login/second-factor` finishes it with a TOTP code, a WebAuthn assertion or a recovery code. Settings under `/v1/account/two-step` (TOTP setup and confirm, security keys, recovery codes, turning off), each change behind a `two-step` reauth token. Trusted-device tokens on login and refresh. The `twofa_config_encrypted` column became the tables above. New config `OCTAPASS_WEBAUTHN_RP_ID`, admin command `reset-two-step`. Details in plan 03 History and `docs/developers/sync-api.md`.
- 2026-10-24 (account 2FA fixes): migration `0007_trusted_devices_follow_devices` ties trusted devices to `devices` (cascade), cuts their lifetime to 30 days and drops rows for missing or revoked devices. New `DELETE /v1/account/two-step/trusted-devices`. See plan 03 History.
- 2026-10-24: attachments built (branch `m7-attachments`, migration 0005). Decisions and deviations from the data model above:
  - **API**: `PUT|GET|DELETE /v1/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` with raw bodies (`Content-Length` required, `411` without), `GET …/attachments` to list, and `GET /v1/account/usage` (`items`, `itemBytes`, `attachmentBytes` and their limits). No presigned URLs: uploads and downloads stream through the server, which keeps object storage private and CORS-free, at the cost of the server's bandwidth. Clients upload first, then list the file in the item's details; attachment changes don't bump the vault revision.
  - **Table** `attachments(vault_id, item_id, id, object_key, size, created_at)` with a foreign key to the item and no cascade, so every path that removes items must remove their attachments first; `encrypted_metadata` from the sketch above lives in the item's details instead. `vaults.attachment_bytes` is a running total like `item_bytes`.
  - **Storage** is a trait with a local-directory backend (default, `<data dir>/attachments`) and an S3-compatible backend (`OCTAPASS_S3_BUCKET`, `_ENDPOINT`, `_REGION`, `_ACCESS_KEY_ID`, `_SECRET_ACCESS_KEY`, `_PATH_STYLE`), a hand-written SigV4 client on `reqwest` checked against the AWS documentation's example and tested against an in-process fake S3. Uploads are spooled to `<data dir>/uploads` first (size checked, SHA-256 computed for a signed payload), so a cut-off upload never leaves a partial object. Object keys are 16 random bytes in hex.
  - **Limits**: `OCTAPASS_MAX_ATTACHMENT_BYTES` (1 GiB) per owner over owned vaults, trash included; `OCTAPASS_MAX_FILE_BYTES` (100 MiB) per file, as stored. Both are checked before the body is read and again in the insert transaction (which writes first to take the vault lock). Attachment routes get a 1-hour timeout and a 60-second idle limit instead of the 30-second request timeout.
  - **Deletion** goes through an `attachment_deletions(object_key, attempts, next_attempt_at)` queue written in the same transaction as the row removal (explicit delete, trash purge, vault deletion, account deletion), then drained right after commit and by maintenance, retrying failures with backoff from 1 minute to 1 day. It holds object keys only. `/readyz` also checks storage.
  - **Not done**: emergency contacts can't download a grantor's files (their read-only sync has no attachment access; done since, see below); `admin backup` doesn't exist yet, so the docs ask self-hosters to copy the attachment storage with the database.
- 2026-10-24 (branch `m9-loose-ends`): `GET /v1/emergency-contacts/{id}/vaults/{vaultId}/items/{itemId}/attachments/{attachmentId}` lets a released emergency contact download the grantor's files. It's authorised as the release is (the contact's own record, released) plus the scope (a vault scope only reaches its vault), then served exactly as the grantor's own download, so the grantor's vault membership decides the rest. In the file router (streamed, longer timeout). Login also emails a "new sign-in" notice (plan 03 History).
- 2026-10-25 (branch `m19-master-password`): master password change and reset. `POST /v1/account/password/registration` (stateless OPAQUE registration for a signed-in account) and `PUT /v1/account/password` (reauth purpose `change-password`; swaps the OPAQUE record, KDF, salt and wrapped ASK, optionally the recovery wrapping, and signs out every other device in one transaction). `POST /v1/auth/recover/start` (emails a code; unknown emails get the same answer and no email), `…/verify` (returns the bundle and a 32-byte challenge), `…/registration` and `…/finish` (Ed25519 signature by the account's key, see plan 03 History; signs out every device). New problem type `recovery-expired`, security events `password-changed` and `password-reset`, three emails. No migration: the in-memory store `pending_recoveries` holds resets. Details in `docs/developers/sync-api.md`.
- 2026-10-25 (branch `m21-http-auth`): `POST /v1/security-log/exports` records a `vault-exported` event for the signed-in device; migration `0008_export_events` adds `device_name`, `device_platform`, `export_format` and `export_attachments` (0/1) to `audit_events`, copied from the device row so the entry outlives it. `SecurityEvent` gains `deviceName`, `devicePlatform`, `exportFormat`, `exportAttachments`. Plan 07 History.
- 2026-11-02 (branch `m25-health`): `POST /v1/health/breach-email` (signed in) proxies Have I Been Pwned for one address. Off unless `OCTAPASS_HIBP_API_KEY` is set; `GET /v1/server-info` gains `emailBreachChecks`. Budget per account 60, one back per 30 minutes (`breach_email_per_account`). `OCTAPASS_HIBP_REQUESTS_PER_MINUTE` (default 10) paces every account together: a request waits up to 15 seconds for its slot, then gets a `429`. HIBP's `429` passes on with its `Retry-After`; a refused key or an outage is a `503`, logged without the address. Redirects aren't followed. `OCTAPASS_HIBP_API_URL` needs dev mode. No migration: nothing is stored.
- 2026-11-02 (branch `m25-vault-features`): item history built as sketched above, with `vault_id` in the key (items are keyed by vault). Migration `0009_item_history` (numbered 0025 on its branch, renumbered when the m25 branches were merged). `GET /v1/vaults/{vaultId}/items/{itemId}/history` for any member of the vault (a stranger gets `404`), newest first. A `PUT` that replaces a version keeps it unless the body sets `skipHistory` (bookkeeping such as a HOTP counter), and drops what falls past 10; trash and restore add nothing. No `encrypted_item_key` column: edits keep the item key and a rotation re-wraps the one on the item, so a version opens with the current key. History counts in `vaults.item_bytes`, so against the quota, but it never refuses an edit by itself: only an item's own growth is checked, so an account over quota can still shrink items and clean up. At the limit, history can therefore add at most 10 times an item's size. Rows go with their item by foreign key (`ON DELETE CASCADE`), and the purge gives their bytes back.
- 2026-11-02 (branch `m25-key-rotation`): `PUT /v1/account/secret-key` (reauth purpose `rotate-secret-key`); `POST /v1/vaults/{id}/rotate` takes personal vaults with `wrappedVaultKey` and no grants, which gives them a `key_id`, so the stale-key check now covers them; `PUT /v1/emergency-contacts/{id}/key`; `POST /v1/emergency-contacts/{id}/takeover/registration` and `…/takeover` (reauth purpose `emergency-takeover`); `POST /v1/families/{familyId}/organiser-recovery`. Migration `0010_key_rotation` adds `emergency_contacts.key_stale` and `organiser_recovery` (numbered 0025 on its branch, renumbered when the m25 branches were merged). New security events `secret-key-rotated`, `vault-key-rotated` (also on member removal), `emergency-takeover`, `organiser-recovery-enabled`, `organiser-recovery-disabled`; emails `SecretKeyRotated`, `EmergencyTakeover`. Design in plans 03 and 06.
- 2026-11-02 (branch `m25-teams`): organisations and SSO on the server, migration `0012_organisations` (numbered 0030 on its branch, renumbered when the m25 branches were merged). Tables `organisations`, `org_members`, `org_invites`, `org_groups`, `org_group_members`, `org_vault_groups`, `org_vault_direct`, `org_rotations`, `org_sso`, `org_sso_identities`, `org_events`; columns `vaults.org_id`, `sessions.sso_at`; view `vault_access`, which sync, item writes and attachments read instead of `vault_members`, leaving out organisation vaults while a member breaks the two-step policy. `db/orgs.rs` owns entitlements and `reconcile`, the one place access is taken away; every change that can lower access runs it inside its transaction, under the organisation's lock. An organisation vault is `type = shared` with `org_id`, so clients need no new crypto and `rotate` works unchanged; a rotation clears `org_rotations`. `src/sso.rs` is the OpenID Connect relying party: reqwest with the icon fetcher's public-address resolver, HTTPS only (HTTP in dev mode), no redirects or proxy, 64 KiB bodies, `OCTAPASS_SSO_PRIVATE_NETWORK` for private IdPs. Pending sign-ins live in memory (`pending_sso`, `pending_sso_browsers`, 10 minutes). The server's only HTML outside the web vault is the end-of-SSO page: no script, inline styles, every value escaped. Invite emails name the inviter only, because an organisation's name is free text and reaches addresses with no account; one address gets the emergency-contact recipient limit. Account deletion promotes the longest-serving admin (else member) when the only owner goes, deletes an organisation with its last member, and an organisation vault others are in outlives its sole owner. API in `docs/developers/sync-api.md`.
- 2026-11-02 (branch `m25-connect`): service accounts (plan 03): migration `0013_service_accounts` on SQLite and PostgreSQL (numbered 0040 on its branch, renumbered when the m25 branches were merged), `/v1/vaults/{id}/service-accounts`, `/v1/service-accounts/{challenge,session,sync,items/{id}}`, `serviceGrants` on rotate. `POST /v1/security-log/connect` takes up to 100 sealed entries a request, a burst of 60 requests per account and one more a second. `GET /v1/security-log` lists up to 500 entries of people's events and 500 of machines', so machines can't push people's out.
- 2026-11-03 (branch `m25-integrator`): the m25 migrations were renumbered in merge order, on SQLite and PostgreSQL alike, before any release: `0009_item_history`, `0010_key_rotation`, `0011_key_log`, `0012_organisations`, `0013_service_accounts`. A development database that ran the branch numbers (0025, 0030, 0040) has to be recreated. `GET /v1/orgs/{orgId}/access` grants carry `keyRecord`; item history reads `vault_access`.
- 2026-11-08: push sync and the push relay built. Decisions:
  - **Server** (`src/push.rs`, `db/push.rs`, migration `0014_push`): `push_tokens(device_id, account_id, platform, token UNIQUE, sandbox, updated_at)`, one token per device, and a token registered by a second device moves to it. `push_relay_installations(relay_url, installation_id, installation_key, created_at)`: the server registers in the background at startup and again from maintenance while it has none. `PUT|DELETE /v1/devices/current/push` (`{platform: apns|fcm, token, sandbox}`; `404 push-off` when push is off). `GET /v1/server-info` reports `pushRelay: true` only once the server is registered, not merely configured. Off by default; `OCTAPASS_PUSH_RELAY_URL` without `OCTAPASS_PUSH_RELAY=true` is refused at startup.
  - **What pushes, and when.** Every vault change and membership change wakes each member account's signed-in devices with `sync` (the same places that tell WebSockets, `AppState::vault_changed` and `membership_changed`). `alert` goes to the other person on: a vault shared with them, a family invite, being added as an emergency contact (and the organiser for organiser recovery), an emergency request (to the grantor), a denial, a release (both sides) and the daily reminder of an unanswered request; the emails stay. Changes gather for 2 seconds per server (`batch_delay`), so an import wakes each phone once, and an alert wins over a sync in the same round. The device that made the change is woken too: the server doesn't know which one did, and the extra sync finds nothing.
  - **Best effort.** Pushes aren't queued or retried: a relay that's down, limiting (`429`) or refusing loses that round, and phones still sync on opening and while open. A token the relay calls `unregistered` is deleted. A `401` (installation unknown, say after the relay lost its data) forgets the installation, and the next maintenance round registers again; a `403` (revoked by the relay's operator) stops all pushes until a restart, and the server doesn't register again by itself. A modified server could, which the relay's per-address registration limit keeps in check. Signing a device out deletes its token, and a revoked device is never a target even before then.
  - **Relay** (`apps/push-relay`): its own binary and database (`installations(id, key_hash, created_at, last_used_at, revoked_at)`, SQLite or PostgreSQL); push tokens are never stored or logged, and logs carry counts only. `POST /v1/installations` (5 an hour per address), `POST /v1/push` (bearer key, 1–100 messages, 600 pushes a minute per installation, answers `sent`, `unregistered` or `failed` per message; `401` unknown, `403` revoked, `429` limited), `admin list` and `admin revoke <id>`. APNs over HTTP/2 with an ES256 provider token (`.p8` key, renewed every 40 minutes, once more on `ExpiredProviderToken`); FCM HTTP v1 with a service account's RS256 assertion traded for an access token. Both signatures use ring, as the `rsa` crate never signs. Payloads: APNs `sync` is a background push (`content-available`, priority 5), `alert` names two strings in the app (`title-loc-key`, `loc-key`) so the words are the phone's own, in its language; FCM sends data messages only (`{"octapass": kind}`, normal or high priority), and the app draws its own notice.
  - **Not done:** nothing has been sent to the real APNs or FCM (no credentials; tests use local fakes), and the project's relay isn't deployed, so `OCTAPASS_PUSH_RELAY_URL`'s default (`https://push.octap.app`) is a placeholder until it is. Organisation invites and removals don't push (they reach people by email, often without an account). Only one server instance batches its own changes; several instances each send their own round.
- 2026-11-08: `GET /v1/health/data` (public) serves the security dashboard's signed site lists (plan 06 History): the copy compiled into the server, or a newer one fetched from `OCTAPASS_HEALTH_DATA_URL` (unset by default; every `OCTAPASS_HEALTH_DATA_INTERVAL` seconds, default 86400, at least 60). A fetched file is served only when it's signed by the pinned key and newer than the one served; redirects aren't followed and the body is capped at 1 MiB. It's kept in memory and fetched again at start. Tests run against a stand-in site on 127.0.0.1.
