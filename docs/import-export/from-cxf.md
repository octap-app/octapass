---
title: Import a CXF file
description: Move logins, passkeys, one-time codes, notes, cards and identities into Octa Pass from any password manager that exports the FIDO Credential Exchange Format (CXF).
status: in-progress
sidebar:
  order: 17
---

:::note[In progress]
CXF import and export work in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import cxf`). Everything is read on your device.
:::

The [Credential Exchange Format](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html) (CXF) is the FIDO Alliance's standard for moving passwords and passkeys between apps. Octa Pass reads and writes CXF version 1.0 as a JSON file. Import a CXF file from another app as **Credential Exchange (CXF)**, or [export one](/docs/import-export/export/) to move to another app.

Apps can also hand CXF to each other directly, with no file: on Android (see [moving between password managers on Android](/docs/platforms/mobile/#moving-between-password-managers-on-android)), on iOS 26, and on macOS 26 (see [moving from another password manager on the Mac](/docs/platforms/desktop/#moving-from-another-password-manager-on-the-mac)). Octa Pass shows what the other app sent before anything is saved.

## What comes across

| CXF | Octa Pass |
|---|---|
| `basic-auth`, with the item's websites and Android apps | Login |
| `passkey` (P-256 and Ed25519 keys) | A passkey on the Login, ready to sign in |
| `totp` | The Login's one-time code |
| `note` | Notes |
| `credit-card` | Card |
| `person-name`, `address` | Identity |
| `identity-document`, `passport`, `drivers-license` | ID document. Beside a login or card, their details stay with that item. With a name or address, those become an identity next to it. |
| `api-key` | API credential. Beside a login or card, it stays with that item. |
| `generated-password` | Password |
| `wifi` | Secure note |
| `ssh-key` | SSH key, when its private key reads (OpenSSH, PEM or PKCS#8); a `Passphrase` custom field is kept for exports. PuTTY, DSA and FIDO keys can't be converted, so those items become secure notes. |
| `custom-fields` | Custom fields on a Login, ID document or API credential, or lines in the notes |
| `custom-fields` from an Octa Pass export | The same item back: bank account, software licence, crypto wallet, database or custom item. CXF has no credential for these, so other apps see plain labelled fields. |
| Collections | Tags |
| Item `id` | Kept with the item, so importing the file again updates it |
| Item `creationAt`, `modifiedAt` | Created and last-changed dates |
| Item `favorite` | Favourite |

An item with a login and a card becomes two items. Empty fields are left out.

When Octa Pass exports CXF, an item that came from another app carries that app's created and last-changed dates, so they survive the move.

## What doesn't

- **Files.** A CXF file only names attached files; the files themselves travel separately, which Octa Pass doesn't take yet (on Android it doesn't ask for them). Octa Pass says how many were left out.
- **Passkeys with RSA keys.** Octa Pass signs with P-256 and Ed25519; other passkeys are skipped with a warning.
- Credential types newer than CXF 1.0 are skipped and named in the import summary. A file from a newer major version of CXF isn't read.

## Tested with

Octa Pass checks its CXF import against the example in the CXF specification and against files exported by Dashlane and 1Password (published as test files by Bitwarden), and checks that its own CXF exports import back.
