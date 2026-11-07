---
title: Importers, site matching and local vaults in the core
date: 2026-10-24
summary: The Rust core can now import from Chrome, Firefox, Safari, Bitwarden, 1Password, LastPass, any CSV and authenticator apps, match logins to websites safely, follow sites' password rules, and run a vault on one device with encrypted backups.
tags: [core, extension, security]
---

The foundations for the browser extension (milestone 2) are in `crates/octapass-core`, and available to JavaScript through `@octapass/core`.

- **Import** from Chrome, Edge, Brave and other Chromium browsers, Firefox, Safari and the Passwords app, Bitwarden (including password-protected exports), 1Password (`.1pux` and CSV), LastPass (including secure notes for cards and addresses), any CSV with your own column choices, and authenticator apps (`otpauth://` links and Google Authenticator exports). One-time codes join the matching login you already have. Fields Octa Pass has no place for are kept as custom fields or notes, never dropped. Everything runs on your device.
- **Site matching** that phishing can't fool: logins are suggested by registrable domain from the Public Suffix List, so `paypal.com.evil.io` never gets your PayPal password, and international domain names are compared safely. Per-login rules (exact host, starts with, regular expression, never) and a short list of domains that share accounts, such as google.com and youtube.com. A mismatch between `http` and `https` is flagged.
- **Password rules**: suggested passwords follow a site's rules, from the page or from Apple's open dataset of 436 sites' requirements.
- **Local vaults** for using Octa Pass without an account: the vault is locked with your master password and, where there is one, your device's security chip. Encrypted `.octapass-backup` files restore on any device with your master password or a backup recovery code. **Turn on sync** later creates an account without decrypting or re-encrypting a single item.

Every parser has fuzz targets, the formats are documented with test vectors, and a bug that let unusual characters in a one-time code field crash the core was fixed. See [use without an account](/docs/features/local-vault/) and [import](/docs/import-export/overview/).
