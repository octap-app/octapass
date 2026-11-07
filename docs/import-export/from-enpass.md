---
title: Import from Enpass
description: Move from Enpass to Octa Pass with the JSON export, keeping logins, cards, identities, notes, tags, TOTP secrets, password history and custom fields.
status: in-progress
sidebar:
  order: 10
---

:::note[In progress]
The Enpass importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import enpass`). Everything is read on your device.
:::

## Export from Enpass

1. Open the Enpass desktop app and unlock it.
2. Choose **File → Export** (on some versions, **Menu → File → Export**) and pick the vault.
3. Select the **.json** format, enter your master password and save the file.

Export each vault separately if you have several.

## What's imported

| Enpass | Octa Pass |
|---|---|
| Logins and passwords | Logins. The first username (or email) is the username; other fields become custom fields, hidden when Enpass marks them sensitive. |
| One-time codes | TOTP on the login |
| Password history | Password history on the login |
| Credit cards | Payment cards |
| Identities | Identities. Fields without an Octa Pass place go into the notes. |
| Secure notes | Secure notes |
| Bank accounts (`finance.bankaccount`) | Bank accounts. The login's username and password stay as custom fields. |
| Passports, driver's licences and ID cards | ID documents |
| Software licences | Software licences |
| Databases and servers | Databases and servers |
| Crypto wallets | Crypto wallets |
| Other categories (finance, licences, travel, computer, misc) | Logins when they have a username or password, secure notes otherwise, with every field |

Enpass doesn't publish its template names, so apart from `finance.bankaccount` they're matched loosely on the words in `template_type` (a best guess). Fields of these types are read by field type and English label; any field that isn't recognised, including every field in another language, stays as a custom field and nothing is lost.
| Tags and folders | Tags (`Parent/Child` when nested) |
| Favourites | Favourites |
| Archived items | Imported with the tag `archived` |
| Trashed items | Not imported |
| Attachments | Not imported. Add the files again in Octa Pass. |
| `uuid` | Kept with the item, so importing the file again updates it |
| `createdAt`, `updated_at`, `last_used` | Created, last-changed and last used dates |
| The password field's `value_updated_at` | Password changed date |
| `icon`, `auto_submit`, `subtitle`, `template_type` | Not imported: how Enpass shows and fills the item. The subtitle is made again from the username |

## Import into Octa Pass

Choose **Import → Enpass**, drop the `.json` file, then review and import. See the [import overview](/docs/import-export/overview/). Delete the export file afterwards: it isn't encrypted.
