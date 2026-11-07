---
title: Import from authenticator apps
description: Move TOTP two-factor codes into Octa Pass from Google Authenticator, Aegis, 2FAS, Raivo, andOTP, Ente Auth and other apps, matched to your existing logins.
status: in-progress
sidebar:
  order: 6
---

:::note[In progress]
Authenticator imports work in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/). Everything is read on your device.
:::

| App | Format | How |
|---|---|---|
| Aegis | JSON vault export, plain or encrypted | [Import from Aegis](/docs/import-export/from-aegis/) |
| 2FAS | `.2fas` backup, plain or encrypted | [Import from 2FAS](/docs/import-export/from-2fas/) |
| andOTP | JSON backup, plain or encrypted | [Import from andOTP](/docs/import-export/from-andotp/) |
| Raivo OTP | Password-protected ZIP or the `raivo-otp-export.json` inside it | [Import from Raivo OTP](/docs/import-export/from-raivo/) |
| Ente Auth | Plaintext `.txt` or password-encrypted `.json` | [Import from Ente Auth](/docs/import-export/from-ente-auth/) |
| Google Authenticator | Export QR codes (`otpauth-migration://`), including exports split over several QR codes | Scan them, or add screenshots of them, with **New item → One-time codes from a QR code** in any app. See [moving codes from Google Authenticator](/docs/features/totp/#moving-codes-from-google-authenticator). Or paste the links into a text file and import it as **otpauth:// links** |
| Anything else | A text list of `otpauth://` links, one per line | Import it as **otpauth:// links** |

## Choosing where each code goes

Before anything is saved, Octa Pass lists every code in the file:

- A code whose issuer matches a login (by the login's name or website, and by username when there are several) already shows that login.
- For the others, choose **Change** to search your logins by name, username or website and pick one, or keep the code as an item of its own.
- Logins that already have a one-time code can't take another.

Then **Save**. Codes you didn't link become logins named after the issuer, with the account as the username. Later, **Link to a login** on such an item moves its code into a login. See [linking a code to a login](/docs/features/totp/#linking-a-code-to-a-login).

Importing the same backup again doesn't add copies: a code already in the vault is left alone, and a code whose entry changed updates the login it belongs to. Aegis keeps each entry's `uuid`; 2FAS's `updatedAt` becomes the last-changed date and andOTP's `last_used` the last-used date. The other apps' exports have no ids or dates, so their codes are recognised by their secret.

## Authy

Authy has no official export, so it can't be imported directly. Re-add 2FA on each site: turn 2FA off and on again, then scan the new QR code with Octa Pass.
