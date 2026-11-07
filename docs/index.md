---
title: Octa Pass documentation
description: Documentation for Octa Pass, the free, open-source, end-to-end encrypted password manager for passwords, passkeys, TOTP codes, cards and identities.
status: stable
sidebar:
  order: 0
---

Octa Pass is a free password manager. It keeps every login, passkey and one-time code you own in one encrypted vault, synced to every browser, phone and computer by the free Octa Pass service. The code is open source (MIT), so anyone can check it, and organisations can [run their own server](/docs/self-hosting/overview/) with the same apps.

:::caution[Project status: public alpha]
The free service is open for sign-ups in the web vault at [vault.octap.app](https://vault.octap.app). The apps are built but not in the app stores yet, and nothing has had its external security audit. Each page shows a status badge: `planned`, `in-progress`, `beta` or `stable`. Features that aren't built say so. See the [roadmap](/docs/reference/roadmap/).
:::

## What Octa Pass stores

- **Logins** with passwords, website URLs, TOTP secrets, passkeys and [recovery info](/docs/features/recovery-info/)
- **Passkeys**, synced across your devices
- **Payment cards, identities and addresses** for form filling
- **Secure notes, documents, SSH keys, environments and Wi-Fi networks**
- Planned: bank accounts, API credentials, software licences, ID documents and more

See [item types](/docs/features/item-types/) for the full list.

## Principles

1. **Zero-knowledge.** Your vault is encrypted on your device. The server only ever stores ciphertext. See the [security overview](/docs/security/overview/).
2. **Same code everywhere.** The hosted service runs exactly the published MIT code. Self-hosters get every feature.
3. **No lock-in.** Full [export](/docs/import-export/export/) in open formats, always free.
4. **No ads, no trackers.** Not on the website, not in the apps, not ever.
5. **Safe by default.** [Autofill](/docs/features/autofill/) never fills silently on a domain that doesn't match exactly.

## Where to start

| If you want to… | Read |
|---|---|
| Understand what Octa Pass is | [Overview](/docs/getting-started/overview/) |
| See how your data is protected | [Security overview](/docs/security/overview/) |
| Check platform support | [Support matrix](/docs/platforms/support-matrix/) |
| Run your own server | [Self-hosting overview](/docs/self-hosting/overview/) |
| Move from another password manager | [Import overview](/docs/import-export/overview/) |
| Contribute code or docs | [Contributing](/docs/contributing/overview/) |
| Point an AI agent at these docs | [Docs for AI agents](/docs/contributing/ai-agents/) |
