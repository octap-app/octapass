---
title: Octa Pass stays unlocked while you're logged in
date: 2026-11-05
summary: A new setting, on by default in the desktop and phone apps and the browser extension, opens Octa Pass without a prompt while your device is unlocked. Revealing and copying ask once, and exporting always asks.
tags: [decision, security, desktop, mobile, extension]
---

A locked vault gets in the way. The extension locked after 15 idle minutes and whenever your computer locked, and every unlock was one more prompt. Your browser's own saved passwords don't work like that, so Octa Pass doesn't have to either.

**Settings → Device auth → Stay unlocked while you're logged in to this device** is on by default. While your device is unlocked:

- **Octa Pass opens without a prompt**, and filling your logins doesn't ask: AutoFill on your iPhone or Android phone, auto-type and AutoFill on your computer, and the browser extension. There's no lock timer.
- **Revealing and copying ask once** for Face ID, Touch ID, Windows Hello, your fingerprint or your device password, or your master password if device unlock is off. That covers them until Octa Pass locks, or your device locks or sleeps.
- **Some things always ask:** exporting, saving a private key or `.env` file, your Secret Key, your Recovery Kit and recovery code, changing or resetting your master password, rotating keys and deleting your account.
- **Your master password every 14 days stays.**
- **Lock now** still locks, until you unlock again.

The browser extension opens through the desktop app when the app stays unlocked too. Without the app, it stays unlocked until the browser closes.

It needs a lock on your device: a passcode on your iPhone, a screen lock on Android, a running keyring on Linux. Without one, Octa Pass locks as before and Settings says why. Turn it off to bring back the lock timer and the two device-auth settings, which show greyed out under the switch while it's on.

**If you already use Octa Pass:** the extension switches to the new default unless you changed its lock settings. The desktop and phone apps can't tell a lock setting you picked from one left at its default, so if they had kept any settings they keep locking as before; turn it on in Settings.

This trades some protection for convenience, and the [threat model](/docs/security/threat-model/) says what: anyone who can use your unlocked device can open Octa Pass and fill your logins, but not reveal, copy or export without your device lock. A locked or switched-off device still holds only encrypted data, and the server still sees nothing new. It's a maintainer decision recorded in [plan 18](https://github.com/octapass/octapass/blob/main/plans/18-stay-unlocked.md) and [plan 03](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md). See [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in).
