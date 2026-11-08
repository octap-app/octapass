---
title: Import from 2FAS
description: Move two-factor codes from 2FAS Authenticator to Octa Pass with a plain or password-protected .2fas backup, matched to the logins you already have.
status: beta
sidebar:
  order: 15
---

The 2FAS importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import 2fas`). Everything is read on your device.

## Export from 2FAS

1. In 2FAS, open **Settings → Backup → Export to file**.
2. Choose to protect the file with a password. This is recommended: the file stays encrypted until Octa Pass decrypts it on your device.
3. Save the `.2fas` file.

The same steps work in the Android and iPhone apps.

## What's kept

| 2FAS | Octa Pass |
|---|---|
| TOTP codes (SHA-1, SHA-256, SHA-512, 6 to 8 digits) | The one-time code of a login |
| Service name and account | Login title and username |
| Groups | Tags |
| `updatedAt` | Last-changed date |
| HOTP codes | [Counter-based codes](/docs/features/totp/#counter-based-codes-hotp), with their counter |
| Steam codes, and other hash algorithms | A hidden field on the login, with the full setup. Octa Pass can't show these codes yet. |
| Icons, badges and order | Not imported |

2FAS services have no id of their own. Importing the same backup again recognises codes by their secret, so nothing is added twice.

## How codes are matched

Each code joins the login already in your vault whose name or website matches the code's issuer, and whose username matches the account name when both have one. Codes without a match, or with more than one possible match, become new logins. A login that already has a code is never changed.

## Import into Octa Pass

Choose **Import → 2FAS**, drop the file, enter the backup password if it has one, then review and import. See the [import overview](/docs/import-export/overview/).
