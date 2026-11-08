---
title: Import from Ente Auth
description: Move two-factor codes from Ente Auth to Octa Pass with the plaintext export or the password-encrypted JSON, matched to the logins you already have.
status: beta
sidebar:
  order: 20
---

The Ente Auth importer works in the web vault, the browser extension, the desktop and phone apps, and the [CLI](/docs/platforms/cli/) (`octapass import ente-auth`, alias `ente`). Everything is read on your device.

## Export from Ente Auth

1. In Ente Auth, open **Settings → Data → Export codes**.
2. Choose **Plain text** or **Encrypted**. Encrypted is recommended: the JSON stays encrypted until Octa Pass decrypts it on your device with the export password.
3. Save the `.txt` or `.json` file.

## What's kept

| Ente Auth | Octa Pass |
|---|---|
| Each code | The one-time code of a login |
| Issuer and account | Login title and username |
| `note` in `codeDisplay` | Login notes |
| `tags` in `codeDisplay` | Tags |
| `pinned` in `codeDisplay` | Favourite |
| `lastUsedAt` in `codeDisplay` | Last used date (Ente writes microseconds) |
| `trashed` codes | Skipped, with a warning |
| HOTP codes | [Counter-based codes](/docs/features/totp/#counter-based-codes-hotp), with their counter |
| Steam codes | A hidden field on the login with the full setup. Octa Pass can't show these codes yet. |
| Icons, tap counts and order | Not imported |

### The encrypted export

Ente's encrypted JSON holds the same lines as the plaintext file, encrypted with a key derived from the export password:

```text
{"version": 1, "kdfParams": {"memLimit", "opsLimit", "salt"}, "encryptedData", "encryptionNonce"}
key       = Argon2id(password, salt, t = opsLimit, m = memLimit / 1024 KiB, p = 1, 32 bytes)
plaintext = libsodium secretstream XChaCha20-Poly1305, one authenticated message
```

Octa Pass follows the same scheme as Ente's own `ente auth decrypt`: it accepts the single message that ends with the FINAL tag, or with MESSAGE as older Ente versions wrote it. A stream with more messages, a PUSH or REKEY tag, extra or missing bytes, or any changed byte is refused, and nothing is imported. The export says how much Argon2id memory and how many passes to use; Octa Pass accepts up to 1 GiB and a total work of four passes at 1 GiB, so a crafted file can't freeze the device.

Ente's export has no ids. Importing the same file again finds codes by their secret instead of adding them twice.

## Import into Octa Pass

Choose **Import → Ente Auth**, drop the file, enter the export password if it's encrypted, then review and import. See the [import overview](/docs/import-export/overview/).
