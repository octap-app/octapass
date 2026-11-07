---
title: The recovery map and masked email
date: 2026-10-24
summary: See which email or phone can reset which of your accounts, and give each site its own forwarding address from your own alias provider.
tags: [core, security, website, extension, desktop, mobile]
---

**Recovery map.** **Health → View the recovery map** groups your logins by the email or phone that can reset them: "14 accounts can be reset through ali@example.com". Logins count when they list it as their recovery email or phone, or sign in with that email. For each email, Octa Pass looks for the email account's own login in your vault, and the dashboard flags it when it has no two-step sign-in, since everything behind it is at risk. It's all worked out on your device. Checking recovery emails against breaches isn't done yet: no check today can do it without sending the address, so we left it out rather than send it. See [recovery info](/docs/features/recovery-info/).

**Linked recovery info.** A login's recovery email or phone can now be picked from one of your Identities, or made as a masked email, and stays linked to where it came from.

**Masked email.** Connect SimpleLogin, addy.io, Firefox Relay, Fastmail, DuckDuckGo or Forward Email with your own API token, which is kept encrypted in your vault. Then:

- In the extension, **Use a masked email** in a sign-up form's email field makes an alias for the site, fills it in, and links it to the login it saves.
- In the editor and the generator, make an alias for any site.
- **Masked email → Aliases in use** shows which logins use which alias.

Calls go straight from your device to the provider; the Octa Pass server never sees your token or aliases. Firefox Relay and DuckDuckGo don't allow calls from web pages, so they work in the extension and the apps but not in the web vault. See [masked email](/docs/features/masked-email/) for which provider works where.

Everything is in Arabic too.
