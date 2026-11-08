---
title: Import from Bitwarden
description: Move from Bitwarden or Vaultwarden to Octa Pass with a JSON, password-protected JSON or CSV export, including folders, cards, identities and TOTP secrets.
status: beta
sidebar:
  order: 3
---

The Bitwarden importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import bitwarden-json`, or `bitwarden-csv`). Everything is read on your device.

## Export from Bitwarden

1. In the Bitwarden web vault, go to **Tools → Export vault**.
2. Choose a format:
   - **.json (Encrypted)** with the *password protected* option. This is recommended: the file stays encrypted until Octa Pass decrypts it on your device.
   - **.json**: complete, but plaintext.
   - **.csv**: logins and notes only, without the ids, dates or password history the JSON has.
3. Confirm with your master password and save the file.

The same steps work for Vaultwarden.

## What's imported

Fields as Bitwarden's own export code writes them (`CipherExport` in Bitwarden's `clients` repository).

| Bitwarden field | In Octa Pass |
|---|---|
| `id` | Kept with the item, so importing the file again updates it |
| `creationDate` | Created date |
| `revisionDate` | Last-changed date |
| `name` | Title |
| `notes` | Notes |
| `favorite` | Favourite |
| `folderId` | Tag with the folder's name |
| `collectionIds` (organisation exports) | Tags with the collections' names |
| `fields` (text, hidden, checkbox) | Custom fields with the same names. Hidden fields stay hidden. Linked fields only point at another field, so they're left out |
| `passwordHistory` | Password history, each dated when it was last used |
| `reprompt` | Not imported: Octa Pass has no per-item master password prompt |
| **Login** `username`, `password`, `totp` | Username, password, one-time code |
| `uris` with `match` | Websites, each with its match rule: *base domain* becomes *every part of this domain*, *exact* becomes *starts with*, and no rule (Bitwarden's default) uses [Octa Pass's default](/docs/features/autofill/#domain-matching) |
| `passwordRevisionDate` | Password changed date, where the export has it (a best guess: not every Bitwarden version writes it) |
| `fido2Credentials` | Passkeys, with their created date. They're kept but can't sign in yet |
| **Card** | Payment card: cardholder, number, expiry, security code, brand |
| **Identity** | Identity: name, email, phone, address. Title, company, username, SSN, passport and licence numbers go into the notes as `Label: value` lines |
| **Secure note** | Secure note |
| **SSH key** | Secure note with the public key, fingerprint and private key |
| Attachments | Not in Bitwarden exports. Add them again after importing |

### The CSV export

Bitwarden's CSV has logins and secure notes only. Its header is `folder,favorite,type,name,notes,fields,reprompt,archivedDate,login_uri,login_username,login_password,login_totp`; organisation exports have `collections` instead of `folder` and `favorite`.

| CSV column | In Octa Pass |
|---|---|
| `type` | A login, or a secure note when it is `note` |
| `name`, `notes` | Title and notes |
| `folder`, `collections` | Tags (collections are split at commas) |
| `favorite` | Favourite |
| `archivedDate` | A tag named `archived`, with a warning |
| `fields` | Custom fields. Each line is `Name: value`; a line without `: ` continues the value above it, and a field with no value is written as `null`. Fields whose name suggests a secret are hidden. |
| `login_uri` | Websites, split at commas |
| `login_username`, `login_password`, `login_totp` | Username, password and one-time code |
| `reprompt` | Not imported: Octa Pass has no per-item master password prompt |
| Empty login rows | Skipped |

The CSV has no ids or dates, so importing it again relies on duplicate matching: the same website and username, or the same title for a note. Use the JSON export if you want the item ids, creation dates and password history.

## Import into Octa Pass

Choose **Import → Bitwarden**, drop the file, enter the export password if it's protected, then review and import. See the [import overview](/docs/import-export/overview/).
