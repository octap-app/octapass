---
title: Change or reset your master password
date: 2026-10-25
summary: Forgot your master password? Reset it with the recovery code from your Recovery Kit. You can also change it in Settings.
tags: [core, server, security, website, extension, mobile, cli]
---

**Forgot your master password?** on the sign-in and lock screens now resets it with the recovery code from your [Recovery Kit](/docs/getting-started/recovery-kit/). We email you a code, you enter your recovery code and a new password, and you save a new Recovery Kit. See [account recovery](/docs/security/account-recovery/).

- **Still zero-knowledge.** The server never sees your recovery code or your password. Your device opens your account key with the recovery code and proves it did by signing with your account's key, so access to your email alone isn't enough.
- **Your vault stays as it is.** Nothing is re-encrypted; only the wrapping of your account key changes.
- **A new recovery code every time.** The old one stops working, and if the device didn't know your Secret Key you get a new one too.
- **Two-step sign-in still applies.** After a reset you sign in as usual, with the second step if it's on.
- **Every device is signed out**, you get an email, and the reset shows in your security log.

**Change master password** is in **Settings → Security** in the web vault, the desktop app and the native iPhone and Android apps: enter the current password and a new one. Your Secret Key and recovery code stay the same, and your other devices are signed out.

Reset works in the web vault, the browser extension, the desktop app, the native iPhone and Android apps and the [CLI](/docs/platforms/cli/): `octapass change-master-password` and `octapass reset-master-password`, which prints the new Recovery Kit. Developers: the [sync API](/docs/developers/sync-api/#resetting-the-master-password) has the new endpoints.
