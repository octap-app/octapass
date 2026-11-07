---
title: Two-step sign-in
date: 2026-10-24
summary: Your Octa Pass account can now ask new devices for a code from an authenticator app, a security key or a recovery code after the master password.
tags: [server, security, website, extension, desktop, mobile]
---

Turn it on in **Settings → Two-step sign-in**: scan the QR code with any authenticator app, enter a code, and save your 10 recovery codes. From then on, a new device needs your master password, your Secret Key **and** the second step. Devices that are already signed in keep working. See [two-step sign-in](/docs/features/two-step-sign-in/).

- **Methods:** codes from an authenticator app (TOTP), security keys and passkeys (in the web vault), and single-use recovery codes.
- **Only after the password.** The second step is asked only once the master password is proven, so a wrong password never shows whether it's on.
- **Every change asks for your master password** and goes into your security log. Turning it on or off, and using a recovery code, also send you an email.
- **Guessing is stopped.** Five wrong codes end a sign-in attempt. Ten wrong codes pause the second step for a few minutes and email you, because whoever is trying knows your master password and Secret Key.
- **It isn't encryption.** It protects access to your encrypted data on the server; your vault is still encrypted with keys only your master password and Secret Key can open.

For self-hosters: security keys are registered for the web vault's host (`OCTAPASS_WEBAUTHN_RP_ID` to change it), and `octapass-server admin reset-two-step <email>` turns it off for someone who lost every method. Developers: the [sync API](/docs/developers/sync-api/#two-step-sign-in) has the new endpoints and the `second-factor-required` login answer.

**Update after a security review:** a device now stays trusted only while it's in your device list (at most 30 days), turning two-step sign-in on makes every other device ask again, and a new **Ask again** button in Settings does the same at any time. The limit on wrong codes now holds even against many guesses at once, and a sign-in that fails after a correct code no longer uses the code up.

Two-step sign-in is also in Arabic, like the rest of the apps.
