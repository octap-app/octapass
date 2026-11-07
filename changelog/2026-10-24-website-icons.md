---
title: Website icons in your item lists
date: 2026-10-24
summary: Items with a website now show the site's icon instead of a coloured letter. Icons come through your Octa Pass server, never from an icon service, and you can turn them off on each device.
tags: [server, web, extension, desktop, mobile, security]
---

A vault of hundreds of logins was a wall of coloured letters. Now each item with a website shows that site's own icon: in the web vault's lists and item pages, the desktop and phone apps, the extension's popup and the menu it shows in login fields. The letter stays while an icon loads and for sites that have none.

Icons come through **your Octa Pass server**, which fetches them from the websites themselves. No icon service (Google, DuckDuckGo and the like) ever sees the sites in your vault. The trade-off: your server sees which domains it fetches icons for. Requests carry no account or token, the domain is cut down to `bank.com` rather than the full address, and your device keeps the icons so they aren't asked for again.

- **Show website icons** is in **Settings** → **Appearance**, on by default and set on each device. Off means no icon requests at all.
- Self-hosters can turn the proxy off with `OCTAPASS_ICONS=off`. The server only connects to public internet addresses, follows at most three redirects, and re-makes every icon as a small PNG.

See [website icons](/docs/features/website-icons/), [what the server sees](/docs/security/what-the-server-sees/) and the [server configuration](/docs/self-hosting/configuration/#website-icons).
