---
title: Import from Avira
description: Move from Avira Password Manager to Octa Pass with a CSV export, including both of Avira's username columns. Everything is read on your device.
status: beta
sidebar:
  order: 23
---

:::note[Best effort]
Avira doesn't publish its export layout, and this importer has been tested on synthetic files, not on a real Avira export. Check a few items after importing.
:::

The Avira importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import avira`). Everything is read on your device.

## Export from Avira

1. Open the Avira Password Manager dashboard and go to **Settings**.
2. Export your data as a CSV file and save it.

## What's imported

The header is `name,website,username,secondary_username,password`.

| Avira | Octa Pass |
|---|---|
| `name` | Title, or the website's name when empty |
| `website` | Website |
| `username` | Username |
| `secondary_username` | Username when `username` is empty, otherwise a custom field |
| `password` | Password |

The CSV has no notes, ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username.

## Import into Octa Pass

Choose **Import → Avira**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: it isn't encrypted.
