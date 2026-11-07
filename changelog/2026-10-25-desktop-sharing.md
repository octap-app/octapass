---
title: Sharing and emergency access in the desktop app
date: 2026-10-25
summary: The desktop app now shares vaults, runs families, makes one-time share links and handles emergency access, with every key sealed and opened in the app's own process.
tags: [desktop]
---

Until now the desktop app could open vaults shared with you, but sharing itself happened in the web vault. Now the app's **Sharing** screens work as they do in the web vault:

- **Shared vaults:** create one, add people after comparing their fingerprint, give them a role, change it, or remove them. Removing someone gives the vault a new key, so what they kept stops working.
- **Families:** create a family, invite people, accept or decline an invitation, and remove members (the Family vault gets a new key, and pending invitations keep working).
- **Share links:** a one-time link to a copy of an item, with an expiry, a view limit and an optional passphrase. Links open in the web vault; on a self-hosted server, in the web vault that server serves.
- **Emergency access:** choose a contact and a waiting period, approve or deny a request, and, as a contact, open what was released to you, read-only, files included.
- **Devices and the security log** in Settings, and the delete-account screen now lists your devices and the shared vaults only you own.

Keys never reach the app's window: they're sealed, signed and opened by the app's Rust side. See [Desktop apps](/docs/platforms/desktop/#sharing-in-the-app).
