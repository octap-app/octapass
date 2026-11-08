---
title: Import from KeePass and KeePassXC
description: Move from KeePass 2 or KeePassXC to Octa Pass by importing the .kdbx database with its password or key file, or an XML or CSV export.
status: beta
sidebar:
  order: 7
---

The KeePass importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import keepass`). Everything is read on your device.

Octa Pass can read your KeePass database file directly. It's decrypted on your device; the file, its password and its key file never leave it.

## Choose what to import

- **The database (`.kdbx`)**: recommended. It stays encrypted until Octa Pass opens it on your device, and it has everything: groups, tags, custom fields, history and one-time codes. KDBX 3.1 and KDBX 4 both work, from KeePass 2, KeePassXC, KeePassDX, Keepass2Android and other compatible apps.
- **KeePass XML export**: in KeePass 2, **File → Export → KeePass XML (2.x)**. Same content as the database, but in plain text.
- **CSV export**: in KeePassXC, **Database → Export → CSV File**. In KeePass 2, **File → Export → KeePass CSV (1.x)**. CSV leaves out custom fields, tags (KeePass 2) and history, so prefer the database.

Delete plain-text exports once the import is done.

## Import into Octa Pass

Choose **Import → KeePass / KeePassXC** and drop the file. For a database, enter its password, add its key file, or both, exactly as you unlock it in KeePass. Then review the preview and import. See the [import overview](/docs/import-export/overview/).

## What's imported

| KeePass | Octa Pass |
|---|---|
| Entry (title, username, password, URL, notes) | Login, or a secure note when the entry only has notes |
| Additional URLs (KeePassXC) | More URLs on the login |
| Group | A tag with the group's path, such as `Work/Email` |
| Tags | Tags |
| Custom strings | Custom fields, hidden when they were protected in KeePass |
| Entry history | Password history (earlier passwords only) |
| One-time codes: KeePassXC's TOTP, KeePass's own TOTP settings, KeeOtp and KeeTrayTOTP | TOTP on the login |
| Expiry date | A custom field "Expires" |
| Recycle Bin | Left out |
| Attachments | Not imported: save them from KeePass and add them to the items |
| `UUID` | Kept with the item, so importing the database again updates it |
| `CreationTime`, `LastModificationTime`, `LastAccessTime` | Created, last-changed and last used dates. KeePass also counts opening an entry as using it |
| Auto-Type: default sequence and window titles | The login's [auto-type](/docs/platforms/desktop/#auto-type) sequence and windows. A window's own sequence isn't kept, and disabled auto-type is left out |
| KeePassXC passkeys (`KPEX_PASSKEY_*`) | Passkeys on the login, which can sign in |
| Icons, colours, `UsageCount`, `LocationChanged` | Not imported: how KeePass shows the entry |

The KeePassXC CSV (`"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"`) brings the created and last-changed dates, but no ids: importing it again finds the same logins by website and username. KeePass 2's CSV (`Account,Login Name,Password,Web Site,Comments`) has no dates.

HOTP setups (KeeOtp's `type=Hotp` and KeePass's own `HmacOtp-` fields) become [counter-based codes](/docs/features/totp/#counter-based-codes-hotp), with their counter. Steam codes can't be computed by Octa Pass yet; they're kept as hidden fields, and the preview tells you which entries have one.

## What can't be imported

- **YubiKey challenge-response** databases: remove the YubiKey from the database's credentials in KeePassXC first (you can add it back afterwards).
- **KeePass 1 (`.kdb`)** databases: open them in KeePass 2 or KeePassXC and save them as `.kdbx`.
- **Extreme key derivation settings.** To keep your device responsive, Octa Pass refuses databases with more than 20 million AES-KDF rounds, or with Argon2 using more than 1 GiB of memory or more than 16 GiB in total (memory × iterations). Lower the settings under **Database → Database settings → Security** (KeePassXC) or **File → Database settings → Security** (KeePass), save, and import again. Settings tuned to one second on a fast computer are fine, but can take a minute or more to open in the web vault.
- Auto-Type settings, icons and colours have no place in Octa Pass and are skipped.
