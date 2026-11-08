---
title: Ask on every fill, now on the iPhone, iPad and Android
date: 2026-11-08
summary: With Stay unlocked off, the phone apps now have the switch the desktop and the extension have, and AutoFill fills without asking while the app is unlocked when you turn it off.
tags: [mobile, security]
---

The phone apps now have **Settings → Device auth → Ask on every fill**, as the desktop app and the browser extension do. It's per phone, never synced, and on by default. Before, with **Stay unlocked** off, AutoFill on the iPhone and iPad and the autofill and passkey services on Android asked for Face ID, your fingerprint or your screen lock on every fill, whatever you wanted.

- **On:** every fill asks, as before.
- **Off:** AutoFill fills without asking **while the Octa Pass app is unlocked**, with the same warning the desktop shows. Once the app locks (by auto-lock, in the background or with **Lock now**), the next fill asks again.
- **Stay unlocked on** (the default): the switch is greyed out, since filling doesn't ask.
- **A phone with no passcode or screen lock** keeps asking for your master password.

AutoFill runs apart from the app, so the app hands it a short-lived key while it's unlocked. The key is kept the way the Stay unlocked key is, behind your phone's own lock, and it stops working when the app's auto-lock time runs out, even if the app never got to delete it. Exporting and your Secret Key still ask every time, and nothing changes on the server.

See [the two device-auth settings](/docs/features/biometric-unlock/#two-device-auth-settings) and the [security model](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md).
