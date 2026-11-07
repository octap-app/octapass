---
title: Import from Zoho Vault
description: Move from Zoho Vault to Octa Pass with a General CSV or Zoho Vault CSV export, including custom fields, folders, tags and one-time codes.
status: in-progress
sidebar:
  order: 22
---

:::note[Best effort]
The Zoho Vault importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import zoho-vault`). Zoho doesn't publish its export layout, and this importer has been tested on synthetic files, not on a real Zoho export. Check a few items after importing. Everything is read on your device.
:::

## Export from Zoho Vault

1. Sign in to Zoho Vault and open **Export Passwords**.
2. Choose **All Passwords** and **All Folders**, then **General CSV** or **Zoho Vault CSV**. Zoho Vault CSV keeps more.
3. Confirm and save `ZohoVault_export.csv`.

## What's imported

| Zoho Vault | Octa Pass |
|---|---|
| `Password Name` or `Secret Name` | Title |
| `Password URL` or `Secret URL` | Website |
| `SecretData` and `CustomData` lines such as `User Name:` and `Password:` | Username and password |
| Other `SecretData` and `CustomData` lines | Custom fields; ones that look like secrets stay hidden |
| `TOTP` or `login_totp` | One-time code |
| `Notes`, `Description` | Notes, with the description on its own line first |
| `Tags`, `Folder Name` | Tags |
| `Favorite` | Favourite |
| `SecretType`, `Classification` | Left out |

An entry with notes and no other fields becomes a secure note. A `SecretData` line without a colon is added to the line above it. Any other column becomes a custom field.

The CSV has no ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username.

## Import into Octa Pass

Choose **Import → Zoho Vault**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: Zoho doesn't encrypt it.
