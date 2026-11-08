---
title: Import from 1Password
description: Move from 1Password to Octa Pass with a 1PUX or CSV export, keeping item types, tags, TOTP secrets and notes, and learn what each format preserves.
status: beta
sidebar:
  order: 2
---

The 1Password importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import 1password`). Everything is read on your device.

## Export from 1Password

1. Open the 1Password desktop app and unlock it.
2. Choose **File → Export** and select the account.
3. Pick **1PUX** (recommended) or **CSV**, and enter your 1Password password when asked.
4. Save the file somewhere you'll remember, and delete it after importing.

## Which format to use

| | 1PUX | CSV |
|---|---|---|
| Logins, passwords, URLs | Yes | Yes |
| Item types (cards, identities, notes…) | Kept | Mostly flattened to logins/notes |
| Tags and vault structure | Kept | Limited |
| TOTP secrets | Yes | Yes |
| Custom fields and sections | Kept as custom fields | Partly |
| Attachments | Metadata only (files must be re-added) | No |
| Passkeys | No (use CXF where available) | No |

## What's imported

### 1PUX

Fields as described in 1Password's [1PUX format](https://support.1password.com/1pux-format/).

| 1PUX field | In Octa Pass |
|---|---|
| `uuid` | Kept with the item, so importing the file again updates it |
| `createdAt`, `updatedAt` | Created and last-changed dates |
| `favIndex` | Favourite |
| `state: archived` | Imported, with the tag `archived`. Deleted items are skipped |
| `categoryUuid` | Item type: logins, passwords, cards, identities and notes become the same type, and so do bank accounts, databases, servers, API credentials, software licences, crypto wallets, passports and driver licenses (the category numbers and field ids come from Bitwarden's 1PUX importer and are a best guess for wallets). Social security numbers become ID documents of the type "Other". Other categories (membership, router…) become logins when they hold a username or password, secure notes otherwise |
| `overview.title`, `overview.tags` | Title and tags. With several vaults, the vault name is added as a tag |
| `overview.url`, `overview.urls` | Websites |
| `details.loginFields` | Username and password. Other form fields become custom fields (passwords hidden) |
| `details.sections` | Custom fields with their titles, concealed fields hidden. One-time codes become the login's code. On cards and identities, the known fields (number, expiry, name, email, phone, address…) fill the item; the rest go into the notes |
| `details.passwordHistory` | Password history, dated when each password was replaced |
| `details.notesPlain` | Notes |
| Documents and attachments | Not imported yet: the item comes in without its file |

### CSV

The 1Password 8 header is `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`.

| CSV column | In Octa Pass |
|---|---|
| `Title`, `Url`, `Username`, `Password` | Title, website, username, password |
| `OTPAuth` | One-time code |
| `Favorite` | Favourite |
| `Archived` | The tag `archived` |
| `Tags` | Tags |
| `Notes` | Notes |
| Any other column | Custom field with the column's name |

The CSV has no ids or dates. Importing it again finds the same logins by website and username.

## Import into Octa Pass

Choose **Import → 1Password**, drop the file, review the preview, pick a vault and import. See the [import overview](/docs/import-export/overview/).

## After importing

- Check the [security dashboard](/docs/features/security-dashboard/) for reused or breached passwords.
- To move passkeys, use the [Credential Exchange Format](/docs/features/passkeys/#moving-passkeys-between-managers) when both apps support it. Otherwise, add a new passkey on each site.
