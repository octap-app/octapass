---
title: Export
description: Export your full Octa Pass vault at any time as an encrypted file with your attachments, plaintext JSON, CSV or the FIDO Credential Exchange Format, with no lock-in and no fees.
status: in-progress
sidebar:
  order: 21
---

:::note[In progress]
Every format works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/). Go to **Settings → Export**.
:::

## Formats

| Format | Contents | Use it for |
|---|---|---|
| **Encrypted** (`.octapass`) | Everything, attached files included, encrypted with a password you choose | Backups, and moving to another Octa Pass account |
| **JSON** (plaintext) | Everything except attached files | Scripts and other tools. Anyone who opens the file can read it. |
| **CSV** | One row per item: Chrome-style columns plus `type`, `totp` and `notes`. Cards, identities, Wi-Fi settings and custom fields go in the notes as `Label: value` lines. Imported back into Octa Pass as **Other app (CSV)**, logins, Wi-Fi networks, cards, identities, notes, bank accounts, licences, ID documents, databases and wallets come back as what they were; other types become notes. | Moving to almost any other manager |
| **CXF** | Logins, passkeys, one-time codes, notes, cards, identities, SSH keys, ID documents and API credentials in the [FIDO Credential Exchange Format](/docs/import-export/from-cxf/). Bank accounts, software licences, crypto wallets, databases and custom items go as labelled fields, and come back as the same item when imported into Octa Pass. Custom templates and scans stay out. | Moving to another manager that supports CXF |

CXF has no place for password history, recovery info or attached files, so those stay behind. It carries SSH keys as `ssh-key` credentials with their private key in PKCS#8; DSA and FIDO keys can't be converted and are reported as left out. The encrypted export keeps all of it.

On Android, another password manager can take your items straight from Octa Pass, as CXF and without a file: start the import in that app and pick **Octa Pass**. See [moving between password managers on Android](/docs/platforms/mobile/#moving-between-password-managers-on-android).

## The encrypted export

Choose a password for the file when you export: at least 10 characters, and not your master password. You'll need it to open the file; we can't recover it.

To bring the file back, go to **Settings → Import**, choose **Octa Pass**, pick the `.octapass` file and enter its password. Everything goes into your Personal vault, in the same account or another one, with new keys: items, passkeys, one-time codes, password history, recovery info (still linked to its Identity) and attached files. A vault on this device only (no account) takes the items but can't hold files.

How the file is made:

- The key comes from your export password with **Argon2id** (256 MiB, 3 passes) and a random salt, then HKDF-SHA256.
- The contents are encrypted with **XChaCha20-Poly1305** in 64 KiB chunks. Each chunk's nonce includes its position and whether it's the last, so a file that was cut short, reordered or changed doesn't open. The header, with the Argon2id settings, is authenticated too.
- Inside is a ZIP with `export.json` (the plaintext JSON format) and one file per attachment. Octa Pass writes and reads it a piece at a time, so a large vault doesn't need to fit in memory twice.

The format is specified in the source: `crates/octapass-core/src/export/archive.rs`.

## Safeguards

- Exporting needs your **master password** again, even when the vault is unlocked. That includes another Android app taking your items, which also names the app first.
- Plaintext exports (JSON, CSV, CXF) show a warning. Delete the file when you're done.
- Every export is added to your account's **security log** (Settings → Security log): which device exported, when, the format, and whether the file holds your attached files. The log never gets anything from the vault itself. Exporting works offline too; the entry is then missing. Android's export to another app (from Android's settings, through Octa Pass's Credential Manager service) isn't logged yet.
- Letting teams turn off plaintext export comes later.

## From the CLI

```bash
octapass export --encrypted --output backup.octapass
octapass export --format json --output backup.json
octapass export --format cxf --output export.cxf.json
octapass export --format csv > logins.csv
octapass import octapass backup.octapass
```

`octapass export` asks for the master password, then for the encrypted file's password twice. With `--password-stdin`, put the master password on the first line and the file's password on the next. Files written with `--output` are readable only by you.

Self-hosters can also back up the whole server. See [backups](/docs/self-hosting/backups/).
