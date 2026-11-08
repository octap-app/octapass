---
title: Octa Pass documentation
description: Documentation for Octa Pass, the free, open-source, end-to-end encrypted vault for everything sensitive, from passwords and passkeys to SSH keys, secrets, IDs and files.
status: stable
sidebar:
  order: 0
---

Octa Pass keeps everything sensitive in one encrypted vault. It does everything a password manager does, for every login, passkey and one-time code you own, and keeps the rest in the same place: SSH keys, API keys and `.env` files, cards and bank accounts, passports and IDs, crypto wallets, Wi-Fi networks and whole folders of files. It all syncs to every browser, phone and computer by the free Octa Pass service. The code is open source (MIT), so anyone can check it, and organisations can [run their own server](/docs/self-hosting/overview/) with the same apps.

:::caution[Project status: public alpha]
The free service is open for sign-ups in the web vault at [vault.octap.app](https://vault.octap.app). The apps are built but not in the app stores yet, and nothing has had its external security audit. Each page shows a status badge: `planned`, `in-progress`, `beta` or `stable`. Features that aren't built say so. See the [roadmap](/docs/reference/roadmap/).
:::

## What Octa Pass stores

- **Signing in:** logins with passwords, website URLs, TOTP secrets, [passkeys](/docs/features/passkeys/) and [recovery info](/docs/features/recovery-info/), plus [masked emails](/docs/features/masked-email/)
- **Money:** payment cards, bank accounts, crypto wallets and software licences
- **Identity:** identities and addresses for form filling, passports, driver's licences and national IDs with their scans
- **Developer secrets:** [SSH keys](/docs/features/ssh-keys/) with an SSH agent, API credentials and OAuth tokens, [environments and `.env` files](/docs/features/environments/), databases and servers, and [certificates and keys](/docs/features/developer-toolkit/)
- **Files:** [documents and attachments](/docs/features/attachments/), [Safes](/docs/features/octa-pass-safe/) (folders that lock with your vault) and [file encryption](/docs/features/file-encryption/) for you or anyone else
- **Everything else:** secure notes, [Wi-Fi networks](/docs/features/wifi/) and custom items with your own fields

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
