---
title: Bitwarden CSV, Raivo OTP, Ente Auth and encrypted Proton Pass imports
date: 2026-10-26
summary: Import from Bitwarden's CSV, Raivo OTP, Ente Auth plain or encrypted exports, and Proton Pass's PGP-encrypted ZIP. Importing an authenticator backup again now updates its codes instead of copying them.
tags: [core, cli, desktop, mobile, extension]
---

Five more ways to move into Octa Pass, all read on your device:

- **Bitwarden CSV**, from an individual vault or an organisation. Folders and collections become tags, custom fields keep their multi-line values, and archived items are tagged `archived`. The JSON export still has the ids and dates the CSV lacks.
- **Raivo OTP**: the password-protected ZIP export, or the `raivo-otp-export.json` inside it.
- **Ente Auth**: the plaintext export, and the password-encrypted JSON. Octa Pass implements Ente's own scheme (Argon2id and libsodium secretstream), so the export's password is all you need.
- **Proton Pass PGP-encrypted exports**: the ZIP with a passphrase now works in every app, including the web vault and the extension. The web vault loads a larger core only for this kind of file.

Authenticator backups are now as careful with re-imports as password-manager imports: Aegis keeps its ids, 2FAS's `updatedAt` and andOTP's `last_used` become dates, and a code already in your vault isn't added again. A changed code updates the login it belongs to and keeps what you've added since.

Dashlane's `.dash` secure archive is still not supported: its format isn't documented. Use the CSV or JSON export instead, which has everything Dashlane exports.

See the per-app field tables in [import and export](/docs/import-export/overview/), including the new [Raivo OTP](/docs/import-export/from-raivo/) and [Ente Auth](/docs/import-export/from-ente-auth/) pages.
