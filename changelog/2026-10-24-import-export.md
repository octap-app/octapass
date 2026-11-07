---
title: Encrypted export, CXF and ten new importers
date: 2026-10-24
summary: Export your whole vault, attached files included, as one encrypted file, move passkeys and passwords to any app that speaks CXF, and import from KeePass, Proton Pass, Dashlane, Keeper and more.
tags: [core, security, cli, desktop, mobile, extension, docs]
---

**Encrypted export.** **Settings → Export → Encrypted** saves everything in your vault, attached files included, as one `.octapass` file locked with a password you choose. Import it into another Octa Pass account, or the same one, and every item comes back with its passkeys, one-time codes, password history, recovery info and files. The file is encrypted with Argon2id and XChaCha20-Poly1305, and is written and read a piece at a time, so large vaults work too. See [export](/docs/import-export/export/).

**CXF.** Export to, and import from, the FIDO Credential Exchange Format: logins, passkeys, one-time codes, notes, cards and identities move between apps that support it. We test against the example in the standard and against files made by Dashlane and 1Password. See [CXF](/docs/import-export/from-cxf/).

**New importers.** KeePass and KeePassXC (`.kdbx` with a password or key file, XML, CSV), Proton Pass, Dashlane, Enpass, Keeper, NordPass, RoboForm, and the authenticator apps Aegis, 2FAS and andOTP, including their encrypted backups. Every importer now works in the web vault, the browser extension, the desktop and phone apps, and the CLI, and everything is read on your device. See [import](/docs/import-export/overview/).

**Safer exports.** Exporting now asks for your master password again in every app.

**CLI.** `octapass export --encrypted`, `octapass export --format cxf`, and `octapass import` with every new format.

Everything is in Arabic too.
