---
title: Website icons
description: Items with a website show that site's icon instead of a coloured letter. Icons come through your Octa Pass server, never from other companies, and you can turn them off on each device.
status: beta
sidebar:
  order: 17
---

Logins and other items with a website show the site's own icon in lists, on the item page and in the browser extension's menu, so a long list is easier to scan. Until an icon arrives, and for sites without one, the item keeps its coloured initial.

Icons work the same in the web vault, the desktop and phone apps and the browser extension, in English and Arabic.

## Where icons come from

Your device asks **your Octa Pass server** for the icon of each item's website, by its domain only (`bank.com`, not `login.bank.com/account`). The server fetches the icon from that website itself and sends it back as a small picture. Icons never come from Google, DuckDuckGo or any other icon service, so no other company sees the list of sites in your vault.

What this means for privacy:

- **Your Octa Pass server sees which websites it fetches icons for.** The requests carry no account, token or cookie, so the server can't tell whose vault a domain is from, but it does see your IP address for its rate limit (as with any request).
- **The websites see a request from the server**, not from you, the first time anyone on that server needs their icon. The server keeps icons for a week.
- **Your device keeps the icons it got**, so 900 items don't load again on every visit. Someone who can read this device's files could see those icons. Turning icons off, or signing out, deletes them.

Without an account (the extension's [local mode](/docs/features/local-vault/)), icons come through the default Octa Pass server in the same way, and only while the setting is on.

## Turn icons off

Go to **Settings** → **Appearance** → **Show website icons**. It's on by default and set on each device. Off means no icon requests at all, and every item shows its initial again.

If you [run your own server](/docs/self-hosting/configuration/#website-icons), you can turn the icon proxy off for everyone with `OCTAPASS_ICONS=off`. Apps then show initials and stop asking.

## Good to know

- Lists ask for icons only as rows scroll into view, a few at a time.
- In the extension's menu on a web page, the icon is drawn by the extension. The page can't see it, its address or which logins you have.
- Icons are always re-made as plain pictures by the server, so a website can't send anything else through them.
