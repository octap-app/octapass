---
title: Two-step sign-in
description: Ask new devices for a code from an authenticator app, a security key or a recovery code after your master password, so a stolen password and Secret Key aren't enough.
status: in-progress
sidebar:
  order: 15
---

:::note[In progress]
Two-step sign-in works on the sync server, in the web vault, the browser extension and the desktop and mobile apps. Security keys can be added and used in the web vault only; the other apps use the authenticator app or a recovery code.
:::

Two-step sign-in adds a second step when you sign in on a **new device**: after your master password and Secret Key, Octa Pass asks for one of:

- a 6-digit code from an **authenticator app** (any app that supports TOTP, including another password manager)
- a **security key** or passkey, such as a YubiKey or your phone
- one of your single-use **recovery codes**

It protects access to your encrypted data on the server. It isn't part of the encryption: your vault is still encrypted with keys only your master password and Secret Key can open. See [authentication](/docs/security/authentication/#two-step-sign-in).

## Turn it on

1. Open **Settings → Two-step sign-in** and choose **Turn on**.
2. Enter your master password.
3. Scan the QR code with your authenticator app, or type the key shown under it.
4. Enter the 6-digit code the app shows. Two-step sign-in is now on.
5. Save your **10 recovery codes**. They're shown only this once. Keep them with your [Recovery Kit](/docs/getting-started/recovery-kit/).

You get an email whenever two-step sign-in is turned on or off.

## Signing in

Devices that are already signed in keep working. A device asks for the second step when it signs in for the first time, after you sign it out, or after 30 days without being used.

To make every other device ask again at its next sign-in, choose **Settings → Two-step sign-in → Other devices → Ask again**. This doesn't sign them out; to do that, use **Settings → Devices**.

On a new device, sign in as usual. When asked, enter the code from your authenticator app, use your security key, or choose **Use a recovery code**.

After five wrong codes you need to enter your password again. After ten wrong codes for your account, two-step sign-in pauses for a few minutes, the event goes into your security log, and you get an email: whoever is trying knows your master password and Secret Key.

## Security keys

Once two-step sign-in is on, you can add security keys in **Settings → Two-step sign-in** in the web vault. You can add up to 10.

Security keys are tied to the web vault's address, so they work when you sign in on the web vault. The browser extension and the desktop and mobile apps ask for a code from your authenticator app or a recovery code instead.

## Recovery codes

- Each code works once. Settings shows how many you have left.
- **New recovery codes** replaces all of them.
- Using one sends you an email, so you know if someone else did.

## Lost your authenticator and recovery codes?

- If you still have a device that's signed in, open Settings there and set up a new authenticator app, make new recovery codes, or turn two-step sign-in off.
- Otherwise the server's administrator can turn it off after checking it's you. On a self-hosted server that's `octapass-server admin reset-two-step <email>` (see [configuration](/docs/self-hosting/configuration/#admin-cli)). Your vault stays encrypted throughout: turning two-step sign-in off doesn't give anyone your keys.

## Turn it off

**Settings → Two-step sign-in → Turn off** removes your authenticator app, security keys and recovery codes. Changing anything here asks for your master password first.
