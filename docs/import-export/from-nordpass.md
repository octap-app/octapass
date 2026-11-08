---
title: Import from NordPass
description: Move from NordPass to Octa Pass with a CSV export, including folders, extra websites, custom fields, credit cards, personal info and secure notes.
status: beta
sidebar:
  order: 12
---

The NordPass importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import nordpass`). Everything is read on your device.

## Export from NordPass

1. Open the NordPass app or web vault and go to **Settings → Import and Export**.
2. Select **Export Items**, then confirm with your master password.
3. Save the CSV file (`nordpass_<date>.csv`).

## What's imported

The header is `name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields`.

| NordPass | Octa Pass |
|---|---|
| Passwords (name, URL, username, password, note) | Logins |
| Additional URLs | More URLs on the login |
| Custom fields (text, hidden, date) | Custom fields; hidden ones stay hidden, dates become `YYYY-MM-DD` |
| Credit cards (cardholder, number, CVC, PIN, expiry) | Payment cards; the ZIP code goes in the notes |
| Personal info (name, email, phone, address) | Identities |
| Secure notes | Secure notes |
| Documents (passport, ID card …) | Secure notes with their fields; NordPass doesn't export the files |
| Folders | Tags |
| Passkeys and file attachments | Not included in NordPass's CSV |

The CSV has no ids or dates, so items show the date they were imported. Importing it again finds the same logins by website and username.

NordPass doesn't export one-time codes. Set them up again from each site's security settings.

## Import into Octa Pass

Choose **Import → NordPass**, drop the file, then review and import. See the [import overview](/docs/import-export/overview/).

Delete the export file afterwards: it isn't encrypted.
