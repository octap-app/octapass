---
title: Import from McAfee True Key
description: Move from McAfee True Key to Octa Pass with its CSV export, including logins and, where the file has them, cards and notes. Read on your device.
status: in-progress
sidebar:
  order: 25
---

:::note[Best effort]
The McAfee importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import mcafee`). McAfee doesn't publish its export layout, and this importer has been tested on synthetic files, not on a real export. A McAfee Password Manager CSV is read by column name, as a best guess. Check a few items after importing. Everything is read on your device.
:::

## Export from True Key

1. Sign in, then open the gear icon and **App Settings**.
2. Under **Export Data**, choose **Export**, confirm with your master password, and save the file. It may have no `.csv` ending. That's fine.

Users report that newer versions export logins only, leaving out Safe Notes and Wallet items. Copy those across by hand. Very old versions wrote a JSON file, which isn't supported.

## What's imported

| True Key | Octa Pass |
|---|---|
| `kind` `login`: `name`, `url`, `login`, `password`, `memo` | Logins |
| `kind` `cc`: `title`, `cardholder`, `number`, `expiryDate`, `note` | Cards. An expiry date that can't be read is kept in the notes |
| Other kinds: `title`, `note`, `document_content` | Secure notes |
| `favorite` | Favourite |
| `autologin`, `hexColor`, `protectedWithPassword`, `subdomainOnly`, `type`, `tk_export_version` | Left out |

Any other column becomes a custom field, or a line in the notes for cards and secure notes. The CSV has no ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username.

## Import into Octa Pass

Choose **Import → McAfee True Key**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: it isn't encrypted.
