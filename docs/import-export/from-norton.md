---
title: Import from Norton
description: Move from Norton Password Manager to Octa Pass with its CSV export of logins and notes. Everything is read on your device and nothing is uploaded.
status: beta
sidebar:
  order: 24
---

:::note[Best effort]
Norton doesn't publish its export layout. This importer follows what users have reported, and has been tested on synthetic files, not on a real Norton export. Check a few items after importing.
:::

The Norton importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import norton`). Everything is read on your device.

## Export from Norton

1. Open your Norton Password Manager vault and go to **Settings → Import/Export**.
2. Choose **Plain Text – CSV file (Logins & Notes only)** and export.

Users have reported exports with fewer items than the vault holds, so compare the counts after importing. Norton's CSV leaves out wallet items and addresses.

## What's imported

Files start with two lines about the export, then `Item Type,User Name,Password,Site Name,Login URL,Notes,Secure,Favorite`. An older layout, `Username,Password,Title,URL,Notes`, is read too.

| Norton | Octa Pass |
|---|---|
| `Site Name` or `Title` | Title |
| `Login URL` or `URL` | Website |
| `User Name` or `Username` | Username |
| `Password` | Password |
| `Notes` | Notes |
| `Favorite` | Favourite |
| Rows with only a name and notes | Secure notes |
| `Item Type`, `Secure` | Left out |

Any other column becomes a custom field. The CSV has no ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username.

## Import into Octa Pass

Choose **Import → Norton**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: it isn't encrypted.
