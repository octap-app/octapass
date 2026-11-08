---
title: Overview
description: What Octa Pass is, who it is for, how the free hosted service and self-hosting relate, and what you can expect before the first public release.
status: in-progress
sidebar:
  order: 1
---

:::note[In progress]
Octa Pass is in public alpha. The free service is open for sign-ups in the web vault at [vault.octap.app](https://vault.octap.app). The apps are built and tested, and they're coming to the app stores soon. See the [roadmap](/docs/reference/roadmap/).
:::

Octa Pass is a free, encrypted home for everything sensitive. It's a password manager, an alternative to 1Password, Bitwarden, LastPass and Dashlane, and it also keeps the rest of what you'd never want to lose or leak: SSH keys, API keys and `.env` files, IDs, cards, crypto wallets and whole folders of files. You create an account on the free Octa Pass service, install the apps, and your vault syncs everywhere. It is built around four ideas:

- **Free, with nothing to set up:** unlimited passwords, passkeys and devices, family sharing for up to 6 people and 1 GB for files. No trial, no ads.
- **Everything sensitive in one vault:** passwords, [passkeys](/docs/features/passkeys/), [TOTP codes](/docs/features/totp/), cards, bank accounts, passports and IDs, [SSH keys](/docs/features/ssh-keys/), [`.env` files](/docs/features/environments/), crypto wallets, [Safes](/docs/features/octa-pass-safe/), [masked emails](/docs/features/masked-email/) and the [recovery details](/docs/features/recovery-info/) of each account. See [item types](/docs/features/item-types/).
- **End-to-end encryption:** encryption happens on your devices. The server, including the people who run it, can't read your vault. See [encryption](/docs/security/encryption/).
- **Open source:** the service runs published MIT code that anyone can audit. If you want to, you can also [run your own server](/docs/self-hosting/overview/) and point the same apps at it.

## Who it is for

1. People leaving a paid or closed password manager over price or trust.
2. Families who share some logins and keep others private (families of up to 6 are free).
3. Developers who want their SSH keys behind an [SSH agent](/docs/features/ssh-keys/#ssh-agent), secrets out of their repos, and a [CLI](/docs/platforms/cli/); and organisations that need to run their own server.
4. Anyone who keeps passport scans, tax returns or seed phrases in a folder or a notes app today.

Small teams and organisations are planned for 1.0.

## How it works

1. You create an account with your email and a **master password**. Your device also generates a **Secret Key** and a **recovery code** and puts both in your [Recovery Kit](/docs/getting-started/recovery-kit/).
2. Your device derives encryption keys from the master password and Secret Key. It encrypts each item before anything is uploaded.
3. The [sync server](/docs/developers/sync-api/) stores the ciphertext and notifies your other devices of changes.
4. Each device decrypts locally after you unlock it with your master password, or with [biometrics](/docs/features/biometric-unlock/) on a trusted device.

## Hosted or self-hosted

| | Octa Pass Cloud (free) | Self-hosted |
|---|---|---|
| Code | Published MIT code | The same code |
| Features | All | All |
| Attachments | 1 GB per account | You choose |
| Data location | EU by default | Your server |
| Who runs it | The Octa Pass project | You |

The free Octa Pass service is the default in every app. To use your own server, choose **Self-hosted** at sign-in; see [connect the apps to your server](/docs/self-hosting/connect-apps/).

## Not planned

- Ads, analytics SDKs or third-party trackers
- Reading your email inbox or SMS
- Masked phone numbers
- Storing any of your data unencrypted
