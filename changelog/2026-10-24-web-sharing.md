---
title: Sharing, families, share links and emergency access in the web vault
date: 2026-10-24
summary: The web vault can now share vaults, run a family, send one-time share links and set up emergency access. Changes from other devices arrive live, imports are faster, and you can see and sign out your devices.
tags: [web, security]
---

The sharing features the server got earlier today now have screens in the web vault. See [sharing](/docs/features/sharing/) and [emergency access](/docs/features/emergency-access/).

## What's new

- **Shared vaults.** Create one from the sidebar, add people by email and give each a role: view only, can edit, manager or owner. Before you add someone, Octa Pass shows their key fingerprint to compare with them; members you haven't compared are marked. Removing someone gives the vault a new key straight away. The vault's name is encrypted too.
- **Your device checks every shared key.** If the signature on your copy of a vault key doesn't check out, the vault stays closed with a warning instead of being used.
- **Families.** Create a family of up to 6 people with a shared Family vault, invite, accept, leave or remove, all under **Sharing → Family**.
- **Share a copy.** Any item can go out as a one-time link that works for 1 hour to 30 days and 1 to 100 views, optionally with a passphrase. The person you send it to doesn't need an account: the item is decrypted in their browser, and the key never reaches the server. Old passwords aren't included. Manage and revoke your links under **Sharing**.
- **Move and copy** items between vaults.
- **Emergency access.** Choose trusted contacts with a waiting period, approve or deny their requests, and, as someone's contact, ask for access and open their vault read-only once it's released.
- **Security log** under **Settings → Security**.
- **Devices** under **Settings**: see where you're signed in, rename this device, and sign out others. A device you sign out finds out at once and removes its copy of your vault. The delete-account summary now counts your real devices.
- **Live sync.** Changes from your other devices and from people you share with arrive within moments over a WebSocket. The 30-second check stays as a fallback.
- **Faster imports.** Imports upload up to 1,000 items per request.
