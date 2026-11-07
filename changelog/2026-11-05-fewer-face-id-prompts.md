---
title: Unlocking is enough to reveal and copy
date: 2026-11-05
summary: Once you unlock Octa Pass with Face ID, your fingerprint, your device's lock or your master password, revealing and copying a password don't ask again until it locks.
tags: [decision, security, mobile, desktop, extension]
---

Until now, Octa Pass asked you to confirm it's you every time you revealed or copied a password, even right after you'd unlocked it with Face ID. That's one prompt too many, so it's gone.

Once you've unlocked Octa Pass with your device's lock (Face ID, Touch ID, your fingerprint, Windows Hello, your passcode) or your master password, revealing and copying a password or another field, showing an item as a QR code, and showing an SSH key or an environment's values don't ask again until Octa Pass locks. Auto-lock, locking when Octa Pass goes to the background, and **Lock now** all end it, and the next unlock counts again.

Some things still ask:

- **Every time, however you unlocked:** exporting your vault, saving a private key or an `.env` file, showing your Secret Key or recovery code, changing or resetting your master password, rotating keys, and deleting your account.
- **Revealing and copying too**, when Octa Pass opened without a check: with **Use device auth when Octa Pass opens** turned off, or on a device with no screen lock.

This is a change to when Octa Pass asks, not to how your vault is protected. Nothing about the encryption changes, and nothing new is kept: the "you've already confirmed" mark lives only in memory and is gone when the vault locks. It's a maintainer decision recorded in [plan 03](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md). See [Revealing and copying](/docs/features/biometric-unlock/#revealing-and-copying).
