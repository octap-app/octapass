---
title: Import from Dashlane
description: Move from Dashlane to Octa Pass with the CSV export (a ZIP of CSV files) or an older JSON export, keeping logins, notes, cards, IDs and personal info.
status: in-progress
sidebar:
  order: 9
---

:::note[In progress]
The Dashlane importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import dashlane`). Everything is read on your device.
:::

## Export from Dashlane

1. Open Dashlane in your browser and go to **My account → Settings → Export data**.
2. Choose **Export to CSV**. Dashlane downloads a ZIP with one CSV file per kind of item.
3. Keep the ZIP as it is. If you unzipped it, you can import the CSV files one at a time.

Dashlane's **secure archive** (`.dash`) is not supported. Its container and encryption aren't publicly documented, and there's no independent open-source reader to check a parser against; reverse-engineering it would risk silently losing items and could break with any Dashlane update. Use the CSV export (or the older JSON export) instead: it has every item Dashlane exports in readable form. Older Dashlane desktop apps could export JSON; Octa Pass reads that too.

## What's imported

| Dashlane | Octa Pass |
|---|---|
| Logins (`credentials.csv`) | Logins, with the category as a tag. Extra usernames become custom fields. |
| TOTP (`otpUrl` or `otpSecret`) | TOTP on the login |
| Secure notes (`securenotes.csv`) | Secure notes |
| Payment cards (`payments.csv`) | Payment cards |
| Bank accounts (`payments.csv`) | Bank accounts. An IBAN or BIC in the number columns goes to its own field; the country and anything else stays as a custom field. |
| IDs: passports, ID cards, licences, social security and tax numbers (`ids.csv`) | ID documents with the number, name, dates and place of issue. Social security and tax numbers are the type "Other". |
| Personal info (`personalInfo.csv`) | One identity with your name, email, phone and address. Extra emails, phones and addresses go into its notes. |
| Other files in the ZIP | Skipped, with a warning |
| Passkeys and attachments | Not in Dashlane's CSV export |

### `credentials.csv` columns

The header is `username,username2,username3,title,password,note,url,category,otpUrl` (`otpSecret` before 2024).

| Column | In Octa Pass |
|---|---|
| `title`, `url`, `username`, `password`, `note` | Title, website, username, password, notes |
| `username2`, `username3` | Custom fields "Username 2" and "Username 3" |
| `category` | Tag |
| `otpUrl` / `otpSecret` | One-time code |

The CSV files have no ids or dates. Importing them again finds the same logins by website and username.

### The JSON export

| JSON field | In Octa Pass |
|---|---|
| `id` | Kept with the item, so importing the file again updates it |
| `creationDatetime` | Created date |
| `userModificationDatetime` | Last-changed date |
| `lastUse` | Last used date (a best guess from other apps' importers: Dashlane doesn't document the JSON export) |
| `anonId`, `spaceId`, `localeFormat`, `lastBackupTime` | Not imported: Dashlane's own bookkeeping |
| `login`, `secondaryLogin`, `email` | The first one is the username; the others become custom fields |
| `domain`, `password`, `note`, `otpUrl`, `category` | Website, password, notes, one-time code, tag |
| `BANKSTATEMENT` | Bank account: `BankAccountName` the title, `BankAccountOwner`, `BankAccountBank`, `BankAccountIBAN`, `BankAccountBIC` |
| `PASSPORT`, `IDCARD`, `DRIVERLICENCE`, `SOCIALSECURITYSTATEMENT`, `FISCALSTATEMENT` | ID document. The key names (`fullname`, `number`, `deliveryDate`, `expireDate`, `deliveryPlace`) are a best guess; any other key stays as a custom field. |
| Other fields | Custom fields on logins and bank accounts and ID documents, `Label: value` lines in the notes of other items |

## Import into Octa Pass

Choose **Import → Dashlane**, drop the ZIP (or a CSV or JSON file), then review and import. See the [import overview](/docs/import-export/overview/). Delete the export file afterwards: it isn't encrypted.
