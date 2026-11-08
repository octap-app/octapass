---
title: Import from Kaspersky
description: Move from Kaspersky Password Manager to Octa Pass with its text export or a CSV, including websites, applications, other accounts and notes.
status: beta
sidebar:
  order: 26
---

:::note[Best effort]
Kaspersky's text export is meant for printing and has no published layout. This importer has been tested on synthetic files, not on a real export. Check a few items after importing.
:::

The Kaspersky importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import kaspersky`). Everything is read on your device.

## Export from Kaspersky

1. Open Kaspersky Password Manager and go to **Settings → Import/Export**.
2. Export to a **text file**, or use the CSV export in My Kaspersky.
3. Save the file.

**Text files can only be read in English**, because their field names are in the app's language. If Octa Pass refuses your file, switch Kaspersky to English and export again.

## What's imported

| Kaspersky | Octa Pass |
|---|---|
| **Websites** | Logins |
| **Applications** | Logins tagged `Applications` |
| **Other Accounts** | Logins tagged `Other Accounts` |
| **Notes** (`Name`, `Text`) | Secure notes |
| `Website name`, `Application`, `Account name` | Title |
| `Website URL` | Website. `https://` is added when there's no scheme |
| `Login` | Username. A `mailto:` at the start is removed |
| `Login name` | Username when there's no `Login`, otherwise a custom field when it differs |
| `Password` | Password |
| `Comment` | Notes |
| Other `Label: value` lines | Custom fields |

Anything up to the entry's `---` line after `Comment` or `Text` is kept as part of it, even a line that looks like a field. A line that can't be understood is left out, with a warning giving its line number.

The CSVs have the header `Account,Login Name,Password,Web Site,Comments` or `Website name;Website URL;Login name;Login;Password;Comment`.

Neither export has ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username. Bank cards, addresses, documents and images aren't in these exports.

## Import into Octa Pass

Choose **Import → Kaspersky**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: Kaspersky doesn't encrypt it.
