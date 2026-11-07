---
title: The sync server runs
date: 2026-10-23
summary: The Octa Pass sync server now handles sign-up, login, encrypted sync and full account deletion, and stores nothing but ciphertext.
tags: [server, security, docs]
---

The first version of the sync server lives in `apps/server`. It's the API the web vault will use in milestone 1.

- **Sign-up and login with OPAQUE.** The server never receives your password or anything it could crack offline. Unknown emails get the same answers as real ones, so the server can't be used to find out who has an account.
- **Encrypted sync.** Items are stored as ciphertext with per-vault revisions. Edits from two devices are detected as conflicts and nothing is silently overwritten. Deleted items wait in the trash for 30 days.
- **Account deletion.** After you confirm your master password and email, one step removes your account and everything in it. Your other devices are signed out and told to wipe their data, the email address is free again immediately, and the only trace is an anonymous daily count.
- **Self-hosting basics.** Configuration through `OCTAPASS_*` variables, SQLite in a data directory, a small non-root Docker image, rate limiting, and an `octapass-server admin` command for invites and account deletion.

The API is documented on the [sync API](/docs/developers/sync-api/) page, with an OpenAPI 3.1 document served by every server. Settings are on the [configuration](/docs/self-hosting/configuration/) page.
