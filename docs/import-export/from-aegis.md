---
title: Import from Aegis
description: Move two-factor codes from Aegis Authenticator to Octa Pass with a plain or password-protected vault export, matched to the logins you already have.
status: beta
sidebar:
  order: 14
---

The Aegis importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import aegis`). Everything is read on your device.

## Export from Aegis

1. In Aegis, open **Settings → Import & Export → Export**.
2. Choose **Aegis (.JSON)**.
3. Leave **Encrypt the vault** on. This is recommended: the file stays encrypted until Octa Pass decrypts it on your device with your Aegis password.
4. Save the file.

## What's kept

| Aegis | Octa Pass |
|---|---|
| TOTP codes (SHA-1, SHA-256, SHA-512, 6 to 8 digits) | The one-time code of a login |
| Issuer and account name | Login title and username |
| Note | Login notes |
| Groups | Tags |
| Favorite | Favorite |
| `uuid` | Kept with the login, so importing the backup again updates it instead of adding a copy |
| HOTP codes | [Counter-based codes](/docs/features/totp/#counter-based-codes-hotp), with their counter |
| Steam, mOTP and Yandex codes | A hidden field on the login, with the full setup. Octa Pass can't show these codes yet. |
| Icons | Not imported |

Aegis exports have no dates. A code that is already in the vault (from an earlier import, or by another route with the same secret) isn't added again; a matching login with a changed entry is updated and keeps what you added in Octa Pass since.

## How codes are matched

Each code joins the login already in your vault whose name or website matches the code's issuer, and whose username matches the account name when both have one. Codes without a match, or with more than one possible match, become new logins. A login that already has a code is never changed.

When a code joins an existing login, its note becomes a separate secure note, so nothing is lost. The code's groups aren't added to that login.

## Import into Octa Pass

Choose **Import → Aegis**, drop the file, enter the export password if it's encrypted, then review and import. See the [import overview](/docs/import-export/overview/).
