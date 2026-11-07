---
title: Import from Keeper
description: Move from Keeper to Octa Pass with a JSON or CSV export, including folders, shared folders, one-time codes, payment cards, contacts and other record types.
status: in-progress
sidebar:
  order: 11
---

:::note[In progress]
The Keeper importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import keeper`). Everything is read on your device.
:::

## Export from Keeper

1. In the Keeper Web Vault or desktop app, open **Settings → Export**.
2. Choose **JSON** (recommended: it keeps record types and structured fields) or **CSV**.
3. Confirm with your master password and save the file.

Keeper Commander's `export --format json` and `export --format csv` files work too. The KeePass (`.kdbx`) and PDF exports aren't Keeper formats: import a `.kdbx` file as [KeePass](/docs/import-export/from-keepass/) instead.

## What's imported

| Keeper | Octa Pass |
|---|---|
| Login records (title, login, password, website, notes) | Logins |
| Extra websites | More URLs on the login |
| One-time codes (`$oneTimeCode`, `TFC:Keeper`) | TOTP on the login |
| Security questions | [Security questions](/docs/features/recovery-info/) on the login |
| Custom fields, hidden fields | Custom fields (secrets stay hidden) |
| Payment cards | Payment cards |
| Contacts and addresses | Identities |
| ID cards, driver's licenses, passports, birth certificates | ID documents, with the number, name and dates in their own fields |
| Bank accounts | Bank accounts. The login, password and website stay with the item. |
| Software licenses | Software licences |
| Database and server records | Databases and servers, with the host split from its port |
| Secure notes | Secure notes |
| Wi-Fi, SSH key and membership records | Logins when they have a username, password or website; secure notes otherwise. Every field is kept. |
| Record types you made yourself | Custom items named after the type, or logins when they have a username, password or website |
| Folders and shared folders | Tags, such as `Work\Dev` or `Family\Shared logins` |
| File attachments | Not included in Keeper's exports; re-add them manually |

### Ids and dates

| Keeper field | In Octa Pass |
|---|---|
| `$record_uid` (CSV from Keeper Commander) | Kept with the item, so importing the file again updates it |
| `uid` (JSON from Keeper Commander) | The same |
| `uid` (JSON from the Web Vault) | Not kept: the Web Vault numbers records 1, 2, 3 in each export, so the number says nothing about the record next time |
| `last_modified` (JSON from Keeper Commander, Unix seconds) | Last-changed date |
| `$type` | The item type (see above) |
| `shared_folders` permissions | Not imported: Octa Pass shares whole vaults instead |

Keeper's exports have no created date or password history. The CSV has no header row: columns are folder, title, login, password, website, notes, shared folder, then field name and value pairs. When a file has no ids, importing it again finds the same logins by website and username.

The CSV export has fewer details than JSON: it has no record types, so every row becomes a login, or a secure note when it only has notes. Its custom fields are kept as they are.

## Import into Octa Pass

Choose **Import → Keeper**, drop the file, then review and import. Octa Pass recognises JSON and CSV on its own. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: it isn't encrypted.
