---
title: Device auth has separate gates for opening and autofill
date: 2026-10-27
summary: Opening Octa Pass and every autofill can now ask for your device's lock independently, with a clear lockless fallback and a master-password gate for secrets.
tags: [security, extension]
---

**Settings → Security → Device auth** now has two per-device switches, never synced:

- **Use device auth when Octa Pass opens** — on by default where your device has a lock. Off, opening asks for your master password instead.
- **Ask on every fill** — on by default. Off, filling works directly while the vault is unlocked, with a warning; a locked vault still asks at least once.

Revealing, copying and exporting always ask, whatever the switches say: your device's lock where available, your master password otherwise. On a device with no lock Octa Pass can use, opening an already-unlocked vault and filling don't prompt, matching Chrome's password manager; after a restart or lock the master password opens the vault, and secrets still need it.

The extension reads the autofill setting in its service worker and opens a small confirmation window for each fill, answered by a fresh passkey check or the master password. Locking or signing out cancels every waiting fill. Vaults on this device only hide account-only settings and use the master password to reveal, copy and export. See [the security model](/docs/security/overview/) and [biometric unlock](/docs/features/biometric-unlock/).
