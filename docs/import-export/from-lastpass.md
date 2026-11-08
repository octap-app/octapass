---
title: Import from LastPass
description: Move from LastPass to Octa Pass with a CSV export, including secure notes in LastPass's special note formats, then rotate passwords affected by the LastPass breach.
status: beta
sidebar:
  order: 4
---

The LastPass importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import lastpass-csv`). Everything is read on your device.

## Export from LastPass

1. Open the LastPass browser extension or web vault.
2. Go to **Account options → Advanced → Export** (or **Advanced options → Export** in the web vault).
3. Confirm your master password. LastPass downloads a CSV file or shows it as text; if it shows text, save it as a `.csv` file.

## What's imported

The header is `url,username,password,totp,extra,name,grouping,fav`.

| LastPass column | In Octa Pass |
|---|---|
| `name` | Title |
| `url` | Website. Secure notes have the placeholder `http://sn`, which is dropped |
| `username`, `password` | Username, password |
| `totp` | One-time code |
| `extra` | Notes. For typed secure notes (`NoteType:`), the fields fill the item |
| `grouping` | Tag with the folder's path (`Work\Dev`) |
| `fav` | Favourite |
| Typed notes | Credit cards become payment cards and addresses become identities. Bank accounts, databases, servers, software licenses, passports, driver's licenses and social security numbers become their own types (social security numbers are ID documents of the type "Other"). Other types with a username or password (email accounts) become logins, and the rest become secure notes. Fields with no place go into the notes as `Label: value` lines |
| Attachments | Not in the CSV |

The CSV has no ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username, and the same notes by title and text.

## After importing

If you used LastPass before its 2022 breach, treat the passwords stored there at that time as exposed. Use the [security dashboard](/docs/features/security-dashboard/) to work through changing your most important ones, starting with email and banking.
