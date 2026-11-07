---
title: Import from andOTP
description: Move two-factor codes from andOTP to Octa Pass with a plain or password-encrypted JSON backup, matched to the logins you already have.
status: in-progress
sidebar:
  order: 16
---

:::note[In progress]
The andOTP importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import andotp`). Everything is read on your device.
:::

andOTP is no longer developed, but its backups still import.

## Export from andOTP

1. In andOTP, open **Backups**.
2. Choose **Backup (encrypted)**. This is recommended: the `.json.aes` file stays encrypted until Octa Pass decrypts it on your device with the backup password. **Backup (plain)** makes an unencrypted `.json` file.
3. Save the file.

Backups made with OpenPGP (`.json.gpg`) can't be imported. Make a password-encrypted or plain backup instead.

## What's kept

| andOTP | Octa Pass |
|---|---|
| TOTP codes (SHA-1, SHA-256, SHA-512, 6 to 8 digits) | The one-time code of a login |
| Issuer and label | Login title and username |
| Tags | Tags |
| `last_used` | Last-used date |
| HOTP codes | [Counter-based codes](/docs/features/totp/#counter-based-codes-hotp), with their counter |
| Steam and mOTP codes | A hidden field on the login, with the full setup. Octa Pass can't show these codes yet. |
| Thumbnails and usage counts | Not imported |

andOTP entries have no id. Importing the same backup again recognises codes by their secret, so nothing is added twice.

## How codes are matched

Each code joins the login already in your vault whose name or website matches the code's issuer, and whose username matches the account name when both have one. Codes without a match, or with more than one possible match, become new logins. A login that already has a code is never changed.

## Import into Octa Pass

Choose **Import → andOTP**, drop the file, enter the backup password if it's encrypted, then review and import. See the [import overview](/docs/import-export/overview/).
