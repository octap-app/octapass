---
title: Import from Proton Pass
description: Move from Proton Pass to Octa Pass with the ZIP, JSON or CSV export, keeping logins, notes, cards, identities, TOTP secrets, passkeys and alias addresses.
status: in-progress
sidebar:
  order: 8
---

:::note[In progress]
The Proton Pass importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import protonpass`). Everything is read on your device.
:::

## Export from Proton Pass

1. Open Proton Pass (the web app, desktop app or browser extension) and go to **Settings → Export**.
2. Pick **ZIP** or **JSON**. The ZIP can be **PGP-encrypted with a passphrase**: Octa Pass reads it on your device with a pure-Rust OpenPGP implementation.
3. **CSV** works too, but it leaves out custom fields, passkeys and Wi-Fi details.
4. Confirm with your Proton password and save the file.

## What's imported

| Proton Pass | Octa Pass |
|---|---|
| Logins (URLs, username, email, password, notes) | Logins. If a login has both a username and an email, the email becomes a custom field. |
| TOTP (`totpUri`) | TOTP on the login |
| Extra fields (text, hidden, TOTP, date) | Custom fields on logins; lines in the notes of other types |
| Notes | Secure notes |
| Credit cards | Payment cards |
| Identities | Identities. Fields without an Octa Pass place (passport, company, social links …) go into the notes. |
| Aliases | Logins with the alias address as the username. The alias keeps forwarding from your Proton account. |
| Passkeys | Kept on the login, but they can't sign you in yet |
| Wi-Fi networks | Logins with the password, SSID and security type |
| SSH keys | Secure notes with every field |
| Custom items | Custom items, with hidden fields and one-time codes kept as those kinds |
| PGP-encrypted export (`data.pgp` or a `.pgp` file) | Decrypted with the export passphrase before anything is read. A wrong passphrase, a changed byte or a cut-off file imports nothing. |
| `itemId` (ZIP and JSON) | Kept with the item, so importing the file again updates it |
| `createTime`, `modifyTime` | Created and last-changed dates (also in the CSV) |
| `lastUseTime` | Last used date, where the export has it (a best guess: we haven't seen it in every export) |
| `pinned` | Favourite |
| Vaults and folders | Tags (vault names only when you export several vaults) |
| URL match settings | Kept where Octa Pass has a matching rule |
| Trashed items | Not imported |
| Attachments | Not imported yet |

The CSV export has no ids. Importing it again finds the same logins by website and username.

The encrypted export is an OpenPGP message with a passphrase (`encryptPassExport` in Proton Pass's own code): OpenPGP.js, iterated and salted S2K, AES-256. Octa Pass uses rPGP, a pure-Rust OpenPGP implementation, so the file is decrypted on the device in every app. The web vault's download is kept small by leaving OpenPGP out; it loads the full build only when you import an encrypted Proton Pass file. An export locked to your Proton account (not a passphrase) still can't be read.

## Import into Octa Pass

Choose **Import → Proton Pass**, drop the `.zip`, `.pgp`, `.json` or `.csv` file, enter the export passphrase if the file is encrypted, then review and import. See the [import overview](/docs/import-export/overview/). Delete the export file afterwards unless it's encrypted.
