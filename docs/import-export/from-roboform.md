---
title: Import from RoboForm
description: Move from RoboForm to Octa Pass with a CSV export, including folders, extra form fields, TOTP keys, bookmarks and safenotes.
status: beta
sidebar:
  order: 13
---

The RoboForm importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import roboform`). Everything is read on your device.

## Export from RoboForm

1. Open the RoboForm app or browser extension and go to **Settings → Account & Data → Export**.
2. Choose **CSV file**, and select **Logins**, **Bookmarks** and **Safenotes**.
3. Confirm with your master password and save the file.

## What's imported

The header is `Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2`.

| RoboForm | Octa Pass |
|---|---|
| Logins (name, URL, match URL, login, password, note) | Logins, with both URLs when they differ |
| TOTP keys | TOTP on the login |
| Extra form fields (`RfFieldsV2`) | Custom fields; password fields stay hidden |
| Bookmarks | Logins with only a URL |
| Safenotes | Secure notes |
| Folders, such as `/Work/Banking` | Tags, such as `Work/Banking` |
| Identities, contacts and file attachments | Not included in RoboForm's CSV |

The CSV has no ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username.

Form fields that repeat the login's username or password aren't added twice.

## Import into Octa Pass

Choose **Import → RoboForm**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: it isn't encrypted.
