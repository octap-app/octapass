---
title: Tighter emergency access and family invites
date: 2026-10-24
summary: Adding emergency contacts is rate limited, a contact for one vault gets nothing that opens your other vaults, and pending family invitations get the new key when someone is removed.
tags: [server, security]
---

Fixes from a security review of sharing and emergency access. See [emergency access](/docs/features/emergency-access/) and the [sync API](/docs/developers/sync-api/#emergency-access).

- **Emergency contacts are rate limited.** Each new contact gets an email, so an account can add about 10, then one every 15 minutes, and one address can be picked about 5 times, then once an hour. Removing a contact and adding them again counts as a new one.
- **One-vault emergency access is only that vault.** When access to a single vault is released, the server now hands over that vault's sealed key and nothing else. Before, it also sent the encrypted copy of your account keys, which your contact couldn't open but didn't need.
- **Family invitations survive a removal.** Removing a family member gives the Family vault a new key. Pending invitations now get the new key in the same step, and any the organiser's device can't re-seal are cancelled, so no invitation ever holds the old key.
