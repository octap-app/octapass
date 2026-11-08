---
title: Import from browsers
description: Import saved passwords into Octa Pass from Chrome, Edge, Brave, Opera, Vivaldi, Arc, Firefox and Safari or Apple Passwords using their CSV exports.
status: beta
sidebar:
  order: 5
---

The browser importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import chrome`). Everything is read on your device.

## Chrome and other Chromium browsers

Chrome, Edge, Brave, Opera, Vivaldi and Arc share one CSV format.

1. Open the browser's password manager (in Chrome: **Settings → Passwords and autofill → Google Password Manager → Settings**).
2. Choose **Export passwords** and confirm with your device password.
3. Import the CSV in Octa Pass with **Import → Chrome/Chromium**.

## Firefox

1. Open `about:logins`.
2. Use the **⋯** menu → **Export passwords** and confirm.
3. Import with **Import → Firefox**.

## Safari and Apple Passwords

1. On macOS, open the **Passwords** app (or Safari's password settings on older versions).
2. Choose **File → Export All Passwords**. The CSV includes notes and TOTP codes.
3. Import with **Import → Apple Passwords**.

On iOS and macOS 26 and later, the Passwords app can also transfer passwords and **passkeys** directly using the Credential Exchange Format. Octa Pass supports this: see [importing a CXF file](/docs/import-export/from-cxf/).

## What's imported

None of these exports carry passkeys, folders or attached files.

### Chrome and other Chromium browsers

The header is `name,url,username,password,note` (Edge leaves out `note`).

| Chrome field | In Octa Pass |
|---|---|
| `name` | Title (the website's name when empty) |
| `url` | Website. Android app logins (`android://…@com.example.app/`) keep the app id |
| `username` | Username |
| `password` | Password, spaces kept |
| `note` | Notes |
| Any other column | Custom field with the column's name, hidden when the name suggests a secret |

Chrome exports no ids or dates, so a login shows the date it was imported. Importing the file again finds the same logins by website and username.

### Firefox

The header is `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged` (from Firefox's `LoginExport.sys.mjs`). Times are in milliseconds.

| Firefox field | In Octa Pass |
|---|---|
| `url` | Website |
| `username` | Username |
| `password` | Password |
| `httpRealm` | HTTP realm, for logins saved from a site's sign-in pop-up instead of a form |
| `formActionOrigin` | A second website, when the form signs in on another site |
| `guid` | Kept with the item, so importing the file again updates it |
| `timeCreated` | Created date |
| `timePasswordChanged` | Password changed date, and the item's last-changed date |
| `timeLastUsed` | Last used date |

Firefox's own sync sign-in (`chrome://FirefoxAccounts`) is skipped.

### Safari and Apple Passwords

The header is `Title,URL,Username,Password,Notes,OTPAuth`. Older Safari versions leave out `Notes`.

| Safari field | In Octa Pass |
|---|---|
| `Title` | Title |
| `URL` | Website |
| `Username` | Username |
| `Password` | Password |
| `Notes` | Notes. A row with only notes becomes a secure note |
| `OTPAuth` | One-time code |

The Passwords app's CSV has no dates or ids. To bring passkeys across, use the [Credential Exchange](/docs/import-export/from-cxf/) transfer instead.

## After importing

- Delete the exported CSV. It's not encrypted.
- Turn off your browser's built-in password saving to avoid duplicate prompts. The [browser extension](/docs/platforms/browser-extension/) explains how.
