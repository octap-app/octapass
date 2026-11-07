---
title: Saving no longer asks you to unlock
date: 2026-11-05
summary: Logins, addresses, cards and API keys you save while Octa Pass is locked wait on your device, sealed, and are added to your vault the next time you unlock.
tags: [decision, security, core, extension, mobile]
---

Saving or adding something must never need an unlock. Until now, a login you typed while the browser extension was locked was never offered for saving, so it was lost. On Android, tapping **Save** on the system's "Save to Octa Pass?" sheet asked for your fingerprint, face or master password every time.

Now a save made while Octa Pass is locked goes into an inbox on that device:

- **Sealed, even from the device.** Each save is encrypted with your account's own public key, using the same hybrid X25519 + ML-KEM-768 sealed box that sharing uses. Only your private keys open it, and they need an unlock. The inbox never syncs, and it holds at most 50 saves.
- **Added at the next unlock.**
  - New logins, addresses, cards and API keys are tagged **Unconfirmed**, so you can review them.
  - A login you already have for that site and username gets the new password, and the old one goes into its history.
  - Anything your vault already has is dropped.
- **The prompt always says Save** while locked, because Octa Pass can't look in a locked vault to tell a new login from a changed password. **Never for this site** still applies.

Signed out, there's nothing to save to, so nothing changes. iOS doesn't give password managers a save request, so there's no save flow on iPhone and iPad.

See [saving while Octa Pass is locked](/docs/features/autofill/#saving-while-octa-pass-is-locked) and the [threat model](/docs/security/threat-model/). The decision and its rules are in plan 03, *Saving while locked*, and plan 05's History.
