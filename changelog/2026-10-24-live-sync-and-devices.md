---
title: Live sync, bulk imports, device management and PostgreSQL
date: 2026-10-24
summary: The sync server now pushes changes to signed-in apps as they happen, takes imports in bulk, lets you see and sign out your devices, runs on PostgreSQL, and closes several abuse paths found in a security review.
tags: [server, security, docs]
---

The sync server gained what the browser extension and the other apps need next.

- **Live sync.** Apps keep a WebSocket open and hear within moments when one of your vaults changes on another device, then sync. The server only says *which* vault changed, never what. Signing a device out, or deleting the account, reaches its open apps the same way.
- **Bulk writes for imports.** Up to 1,000 items go up in one request. Each vault is all or nothing: if one item fails, nothing in that vault is written, and the app is told exactly which item and why.
- **Your devices.** Apps can list your signed-in devices, rename the current one and sign any of them out remotely. A device that has been signed out is forgotten by the server.
- **PostgreSQL.** Self-hosters can point `OCTAPASS_DATABASE_URL` at PostgreSQL 16+ instead of SQLite. The same test suite runs against both.

From an independent security review of the server:

- Sign-up codes can no longer be brute-forced by guessing in parallel or by asking for new codes: guesses are counted atomically, carry over to re-sent codes, and are capped per email per day, as are the codes we send.
- Nobody can lock you out by flooding sign-in attempts for your email. Only failed sign-ins count, separately for each network address, under a much higher overall ceiling. One address also can't crowd out everyone else's sign-ins.
- A deleted account can't be recovered from the server's SQLite files: deleted data is overwritten on disk and the write-ahead log is emptied.
- Each account has a storage quota (50,000 items and 1 GiB of encrypted item data by default, configurable when self-hosting), and sync responses come in pages so they stay a reasonable size.
- Email delivery errors are logged without the recipient's address.

Details are on the [sync API](/docs/developers/sync-api/) and [configuration](/docs/self-hosting/configuration/) pages.
