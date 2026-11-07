---
title: Import overview
description: Import passwords, passkeys and TOTP codes into Octa Pass from 1Password, Bitwarden, LastPass, browsers, KeePass, Proton Pass and 20+ other sources.
status: in-progress
sidebar:
  order: 1
---

:::note[In progress]
Every importer below marked *Available* works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/). Go to **Settings → Import**.
:::

Imports run **entirely on your device**. The export file is read and checked locally, then each item is encrypted before upload. The plaintext file never reaches the server.

## Supported sources

| Source | Formats | Status |
|---|---|---|
| Octa Pass | The encrypted export (with attached files), plaintext JSON. See [export](/docs/import-export/export/). | Available |
| Any CXF-capable manager | FIDO Credential Exchange Format: logins, passkeys, one-time codes, notes, cards, identities, ID documents, API credentials. See [CXF](/docs/import-export/from-cxf/). | Available |
| Google Password Manager and other Android password managers | Straight from the app, no file (Android with Google Play services). See [Android](/docs/platforms/mobile/#moving-between-password-managers-on-android). | Available |
| Chrome, Edge, Brave, Opera, Vivaldi, Arc | CSV. See [browsers](/docs/import-export/from-browsers/). | Available |
| Firefox | CSV | Available |
| Safari / Apple Passwords | CSV | Available |
| Bitwarden, Vaultwarden | JSON, password-protected JSON, CSV. See [Bitwarden](/docs/import-export/from-bitwarden/). | Available |
| 1Password | 1PUX, CSV. See [1Password](/docs/import-export/from-1password/). | Available |
| LastPass | CSV. See [LastPass](/docs/import-export/from-lastpass/). | Available |
| KeePass, KeePassXC | KDBX 3.1 and 4 (with password and key file), XML, CSV. See [KeePass](/docs/import-export/from-keepass/). | Available |
| Proton Pass | ZIP (JSON), PGP-encrypted ZIP with a passphrase, JSON, CSV. See [Proton Pass](/docs/import-export/from-protonpass/). | Available |
| Dashlane | ZIP of CSVs, JSON. See [Dashlane](/docs/import-export/from-dashlane/). | Available |
| Enpass | JSON. See [Enpass](/docs/import-export/from-enpass/). | Available |
| Keeper | CSV, JSON. See [Keeper](/docs/import-export/from-keeper/). | Available |
| NordPass | CSV. See [NordPass](/docs/import-export/from-nordpass/). | Available |
| RoboForm | CSV. See [RoboForm](/docs/import-export/from-roboform/). | Available |
| Zoho Vault | CSV. See [Zoho Vault](/docs/import-export/from-zoho-vault/). | Available, best effort |
| Avira | CSV. See [Avira](/docs/import-export/from-avira/). | Available, best effort |
| Norton | CSV. See [Norton](/docs/import-export/from-norton/). | Available, best effort |
| McAfee True Key | CSV. See [McAfee](/docs/import-export/from-mcafee/). | Available, best effort |
| Kaspersky | Text or CSV. See [Kaspersky](/docs/import-export/from-kaspersky/). | Available, best effort |
| Authenticator apps | Aegis, 2FAS, andOTP, Raivo OTP, Ente Auth (plain or encrypted), `otpauth://` and Google Authenticator links. See [authenticator apps](/docs/import-export/from-authenticator-apps/). | Available |
| Any CSV | Columns recognised by name, Bitwarden's CSV export included. See [other apps](#other-apps-csv). | Available |
| Zoho Vault, Avira, Norton, McAfee, Kaspersky | CSV/TXT, best effort | Planned for 1.0 |

## How an import works

1. **Pick the source.** Each source has a short guide on exporting from that app.
2. **Choose the file**, and its password if it has one (Octa Pass encrypted exports, password-protected Bitwarden or Proton Pass files, KeePass databases and authenticator backups). For KeePass, add the key file if the database uses one.
3. **Import.** Each item is encrypted on your device and uploaded to your Personal vault. One-time codes for logins you already have are added to those logins. Each field goes where it means the same in Octa Pass: the other app's dates, its id for the item, folders as tags, password history. Fields Octa Pass has no place for go into custom fields or notes, never dropped. You see how many items are new, updated and unchanged, what was skipped and why.
4. **Delete the export file.** Unless it's an Octa Pass encrypted export or another password-protected file, anyone who finds it can read it.

Each source's page has a table of every field the app exports and where it goes.

Coming later: a preview with counts per item type before anything is saved, choosing another vault, tagging imported items, and resuming an interrupted import.

## Importing again

You can import the same file again, or a newer export from the same app, without getting copies:

- An item matches one already in the vault by the id the other app gave it, when the export has ids (Firefox, Bitwarden, 1Password 1PUX, Proton Pass, Enpass, Dashlane JSON, Keeper Commander, KeePass, CXF, Aegis).
- Otherwise it matches a duplicate: a login with the same website and username (or the same title, when it has neither), a card with the same number, an identity with the same name and contact details, a bank account with the same title and IBAN or account number, an API credential with the same title, host and username, a software licence with the same title and key, an ID document with the same kind and number, a crypto wallet with the same title and first address, a database with the same host, port, database name and username, a custom item with the same title and template, a note with the same title and text, a document with the same title and notes, an SSH key or key with the same public key, a certificate with the same certificate, an environment with the same project and stage (or the same title, when it has neither). Only the vault you import into is compared.
- An authenticator backup matches codes by the app's id, or by the code's secret when the export has no ids (2FAS, andOTP, Raivo, Ente Auth, `otpauth://` lists). Codes that are already in the vault aren't added again, and a changed code updates the login it belongs to.
- A matching item is **updated** with the file's values. What only Octa Pass has stays: attached files, recovery info, fields the file doesn't have, tags you added. A changed password moves the old one into the password history, dated when the other app says the password changed.
- Websites are merged: the login keeps the ones it has and gains the file's new ones. Apps write one site in different ways (`https://example.com`, `https://example.com/`, `http://www.example.com/login`), and those count as one website, so it isn't added again. The address already in your vault stays, with its [match rule](/docs/features/autofill/#domain-matching). See [one website, listed once](/docs/features/item-types/#one-website-listed-once).
- An item that would come out the same is **unchanged** and isn't saved again.

**Octa Pass's own exports** match the same way, but by each item's own id first, in any of your vaults: an export holds every vault and an import goes into one. So importing a backup again, or importing the same export into another account twice, adds only the items that aren't there yet.

- An item that changed in your vault after the export was made is **kept** as it is. The summary says how many were.
- An item that's newer in the export replaces the vault's version. The vault's attached files and password history stay, and the vault's password joins that history when the export has a different one.
- From an encrypted export, attached files come back to the items that no longer have them.
- An item that links to another (a login's recovery email from an Identity) links to the one already in your vault.

## Dates

An imported item keeps the dates the other app recorded: when it was created, when it last changed, when it was last used and when its password changed. The item shows them instead of the day it was imported, and they're encrypted with the rest of the item. Editing the item in Octa Pass makes its "Last changed" date today's.

## Other apps (CSV)

**Import → Other app (CSV)** reads any CSV with a header row.

- If the header is another app's export that Octa Pass has an importer for (Firefox, Chrome, Safari, LastPass, 1Password, Proton Pass, NordPass, RoboForm, KeePassXC, Dashlane, Zoho Vault, Avira, Norton, McAfee True Key, Kaspersky), the file is read by that importer and the summary says so.
- Bitwarden's CSV export (`folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp`) has its `fields` column split into custom fields, `folder` as a tag and `favorite` as a favourite.

Otherwise, columns are recognised by their names:

| Column names | In Octa Pass |
|---|---|
| `title`, `name`, `account`, `entry` | Title |
| `url`, `website`, `uri`, `login_uri`, `address`, `site` | Website |
| `username`, `login`, `user`, `email` | Username |
| `password`, `pass`, `passwd` | Password |
| `totp`, `otp`, `otpauth`, `2fa` | One-time code |
| `notes`, `note`, `extra`, `comments` | Notes |
| `tags`, `labels` | Tags (split at `,` or `;`) |
| `folder`, `grouping`, `group`, `category` | One tag |
| `favorite`, `favourite`, `fav` | Favourite (`true`, `yes` or `1`) |
| `created`, `created_at`, `creation_date` | Created date |
| `modified`, `last_modified`, `updated`, `revision_date` | Last-changed date |
| `last_used`, `last_accessed` | Last used date |
| `password_changed`, `password_last_changed` | Password changed date |
| `id`, `uuid`, `guid` | Kept with the item, so importing the file again updates it |
| Any other column | Custom field with the column's name, hidden when the name suggests a secret |

Dates can be Unix seconds or milliseconds, or ISO 8601 (`2024-05-01T10:00:00Z`, `2024-05-01 10:00`, `2024-05-01`).

The [CLI](/docs/platforms/cli/) can import too: `octapass import <format> <file>`, into any vault with `--vault`.

## Quality

Every importer is tested against synthetic export files, including Unicode, right-to-left text, multiline notes, quoted CSV fields, malformed rows and 50,000-item files. Every parser is fuzzed.
