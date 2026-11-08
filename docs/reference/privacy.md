---
title: Privacy policy
description: What Octa Pass stores, what the server can and can't see, and what the apps and browser extensions never do with your data.
status: stable
sidebar:
  order: 5
---

Octa Pass is an end-to-end encrypted password manager. This policy covers the apps, the browser extensions and the hosted service at [vault.octap.app](https://vault.octap.app). Last updated 2026-11-08.

## What stays on your device

Your vault's contents (passwords, passkeys, one-time codes, cards, identities, notes, files and every other item) are encrypted on your device before they leave it. Your master password and Secret Key never leave your device.

The browser extension reads the pages you visit only to find login, payment and address fields and to fill them when you ask. Page content is never sent anywhere.

## What the server stores

To sync your vault, the server you use (vault.octap.app by default, or your own) stores:

- your email address, to identify your account and send verification codes and security alerts;
- your encrypted vault data, which it can't read;
- OPAQUE login records, which don't reveal your password;
- device and session records, so you stay signed in on your devices.

The server can't decrypt your items. The details are in [what the server sees](/docs/security/what-the-server-sees/).

## Optional features

- **Breach checks** send only the first 5 characters of a password's SHA-1 hash (k-anonymity), never the password.
- **Site icons**, when turned on, are fetched through the server by domain name.
- **The desktop app connection** uses your browser's native messaging and stays on your computer.

## What we never do

No ads, no analytics, no trackers. We don't sell, rent or share your data, and we don't use it for anything but running the service. The browser extensions declare no data collection.

## Deleting your data

You can export everything at any time, and delete your account from the web vault or the apps. Deleting your account removes your data from the server.

## Contact

Questions about privacy or security: open an issue at [github.com/octap-app/octapass](https://github.com/octap-app/octapass/issues), or report a vulnerability privately as described in the [security policy](https://github.com/octap-app/octapass/blob/main/SECURITY.md).
