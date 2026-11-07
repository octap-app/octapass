---
title: FAQ
description: Answers to common questions about Octa Pass, covering cost, why there are no ads, privacy, forgotten master passwords, self-hosting, platforms and audits.
status: stable
sidebar:
  order: 1
---

## Is Octa Pass available yet?

As a public alpha, yes: create a free account in the web vault at [vault.octap.app](https://vault.octap.app). The apps are built but not in the app stores yet; they're coming soon, and until then you can [build them yourself](/docs/contributing/development-setup/). Nothing has had its external audit, so don't rely on Octa Pass alone for anything important yet. The [roadmap](/docs/reference/roadmap/) shows the beta and 1.0. Follow the [changelog](/changelog/) for news.

## Is it free?

Yes. The hosted service is free with unlimited items and devices, 1 GB of attachments and families of up to 6. The software is free and open source under MIT, and you can [self-host](/docs/self-hosting/overview/) it with every feature.

## Why no ads?

Ad code runs third-party scripts, and a password manager is the last place those belong. Ads also depend on tracking, which goes against the point of a privacy tool. Octa Pass is funded by donations, sponsors and grants instead. A possible paid organisation plan for hosting and support is still undecided; if it happens, its code will be AGPL like everything else.

## How do you pay for free hosting?

Encrypted vaults are small, so hosting is cheap per user. The main costs are attachments, email and servers. Quotas keep them bounded, and donations (GitHub Sponsors, Open Collective), grants and sponsors pay for the rest. Monthly costs will be published.

## Can you see my passwords?

No. Your vault is encrypted on your device with keys derived from your master password and your Secret Key, and the server only stores ciphertext. The server does see some metadata, such as your email and how many items you have. See [what the server sees](/docs/security/what-the-server-sees/).

## What if I forget my master password?

Use the recovery code from your [Recovery Kit](/docs/getting-started/recovery-kit/). If you've also lost that, an [emergency contact](/docs/features/emergency-access/) or family organiser can help if you set one up. Otherwise nobody can recover your vault, including us. That's what zero-knowledge means. See [account recovery](/docs/security/account-recovery/).

## What is the Secret Key?

A random 128-bit key generated on your device and combined with your master password to create your encryption keys. It makes a stolen server database impossible to crack. You type it once per new device, or scan it from your Recovery Kit. See [encryption](/docs/security/encryption/).

## How is Octa Pass different from other password managers?

| | Octa Pass |
|---|---|
| **Bitwarden** | Also open source with a free tier, and a mature, widely used product. Octa Pass adds a Secret Key and OPAQUE login, and makes the self-hosted and hosted versions feature-identical under one AGPL licence. |
| **1Password** | Polished, with a Secret Key design that Octa Pass learns from. 1Password is closed source and paid. |
| **KeePassXC** | Excellent, local-first and open source, with sync left to you. Octa Pass includes sync, sharing and mobile autofill. |
| **Proton Pass** | Open-source clients with built-in aliases, from a company with a paid plan. Octa Pass's server is open source too, and it integrates with existing alias providers. |
| **Apple / Google password managers** | Convenient within one ecosystem. Octa Pass works across all platforms and exports freely. |

All of these are good products. Octa Pass is new and unaudited, and that won't change until 1.0.

## Can I self-host?

Yes. It's the same code as the hosted service, as a single Docker container with SQLite or PostgreSQL. See [self-hosting](/docs/self-hosting/overview/).

## Which platforms will it support?

Chrome, Edge, Firefox, Safari and other browsers; macOS, Windows and Linux; iOS and Android; a web vault; and a CLI. See the [support matrix](/docs/platforms/support-matrix/).

## Can it store passkeys and 2FA codes?

Yes. [Passkeys](/docs/features/passkeys/) and [TOTP codes](/docs/features/totp/) are core features, and both can be imported and exported.

## Is it audited?

Not yet. An independent security audit of everything that ships in 1.0 is required first, and the full report will be published. It's the last step on the [roadmap](/docs/reference/roadmap/). The design and code are open so they can be reviewed early. See the [security overview](/docs/security/overview/).

## Can I import from my current password manager?

Yes, from 1Password, Bitwarden, LastPass, browsers, KeePass, Proton Pass, Dashlane and more. See the [import overview](/docs/import-export/overview/).

## Is "Octa Pass" the final name?

Yes. It was called "Open Pass" during early development and was renamed before the first public release, because "OpenPass" is already the name of another product. The website is [octap.app](https://octap.app).
