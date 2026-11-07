---
title: Import from Raivo OTP
description: Move two-factor codes from Raivo OTP to Octa Pass with its password-protected ZIP export, or the JSON inside it, matched to the logins you already have.
status: in-progress
sidebar:
  order: 19
---

:::note[In progress]
The Raivo OTP importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import raivo`). Everything is read on your device.
:::

## Export from Raivo OTP

1. In Raivo OTP on your iPhone or iPad, open **Settings → Export**.
2. Save the ZIP. Raivo encrypts it with your Raivo master password, so have that ready.
3. Keep the ZIP as it is. The `raivo-otp-export.json` inside it can be imported on its own too.

Raivo also writes an HTML page with QR codes into the ZIP. Octa Pass doesn't read that page: the JSON has everything.

## What's kept

| Raivo | Octa Pass |
|---|---|
| TOTP codes (SHA-1, SHA-256, SHA-512, 6 to 8 digits) | The one-time code of a login |
| Issuer and account | Login title and username |
| `pinned` | Favourite |
| `kind: HOTP` | [Counter-based codes](/docs/features/totp/#counter-based-codes-hotp), with their counter |
| `kind: Steam` and other kinds | A hidden field on the login with the full setup. Octa Pass can't show these codes yet. |
| Icons (`iconType`, `iconValue`) | Not imported |
| Entries without a secret | Skipped, with a warning |

Raivo's export has no ids or dates. Importing the same file again finds the codes by their secret instead of adding them twice. A code that joins a login you already have isn't added to another login.

## Import into Octa Pass

Choose **Import → Raivo OTP**, drop the ZIP (or the JSON inside it), enter the Raivo master password if the file is encrypted, then review and import. See the [import overview](/docs/import-export/overview/).
