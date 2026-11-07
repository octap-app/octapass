---
title: Encryption and keys
description: The Octa Pass key hierarchy and algorithms in detail, including Argon2id, HKDF, XChaCha20-Poly1305, X25519, Ed25519, the Secret Key and per-item keys.
status: in-progress
sidebar:
  order: 2
---

:::note[In progress]
This design is implemented in the Rust core (`crates/octapass-core`) that the web vault runs as WebAssembly. Parameters may still be tuned before 1.0. Changes will be recorded in the [changelog](/changelog/).
:::

## Primitives

| Purpose | Algorithm |
|---|---|
| Password key derivation | Argon2id, memory 64 MiB, iterations 3, parallelism 1. Parameters are stored per account and can be upgraded. |
| Key derivation | HKDF-SHA256, with a distinct `info` label for each purpose |
| Symmetric encryption | XChaCha20-Poly1305 with random 192-bit nonces and associated data |
| Public-key encryption (sharing) | Hybrid X25519 + ML-KEM-768 sealed boxes (HKDF + XChaCha20-Poly1305), with X25519-only boxes for accounts that have no ML-KEM key yet. Not yet reviewed by an outside cryptographer. |
| Signatures | Ed25519 |
| Login | OPAQUE (RFC 9807) over ristretto255 with Argon2id. See [authentication](/docs/security/authentication/). |
| Passkeys | ES256 (P-256) and EdDSA |
| Randomness | The OS CSPRNG (`getrandom`; `crypto.getRandomValues` in WebAssembly) |

All of this is implemented once, in the Rust core, using RustCrypto crates. All key material is zeroed from memory when no longer needed.

Parallelism is 1 because WebAssembly runs Argon2 lanes one after another, so a higher value would only make browser unlock slower.

## Key hierarchy

```text
master password ─NFKD─► Argon2id(salt = HKDF(account_salt, email)) ─► pw_key ─┐
                                                                               ├─► HKDF ─► AUK (Account Unlock Key)
Secret Key (128-bit, made on device) ─► HKDF(salt = account_salt) ─► sk_key ───┘     └──► auth_secret ─► OPAQUE

AUK                  unwraps  ASK (Account Symmetric Key, random 256-bit)
ASK                  unwraps  your private keys (X25519 encryption, Ed25519 signing)
ASK                  unwraps  your personal Vault Keys
your X25519 key      opens    shared Vault Keys (sealed to each member, signed by the sharer)
Vault Key            unwraps  Item Keys (random, one per item)
Item Key             decrypts item overview (title, URLs, icon hint) and item details
Item Key             unwraps  File Keys (random, one per attachment)
File Key             decrypts the attachment's file, in 64 KiB chunks

Recovery Key (256-bit, shown once)               wraps ASK (stored on the server)
Device Key (hardware-backed, biometric-gated)    wraps ASK (stored only on that device)
```

### Derivation in detail

```text
account_salt = 16 random bytes, made at sign-up and returned by prelogin
argon2_salt  = HKDF-SHA256(ikm = account_salt, salt = "octapass/v1", info = email)[0..16]
pw_key       = Argon2id(NFKD(password), argon2_salt, 64 MiB, 3 iterations, 1 lane) → 32 bytes
sk_key       = HKDF-SHA256(ikm = Secret Key, salt = account_salt, info = "octapass/v1/secret-key")
AUK          = HKDF-SHA256(ikm = pw_key ‖ sk_key, info = "octapass/v1/auk")
auth_secret  = HKDF-SHA256(ikm = pw_key ‖ sk_key, info = "octapass/v1/auth")
```

The email is trimmed and lower-cased. The password is NFKD-normalised, so the same password typed on different keyboards gives the same key, but it isn't trimmed. Because the KDF parameters come from the server, apps refuse anything weaker than the defaults: a malicious server can't make your password cheaper to guess.

`auth_secret` is the password input to [OPAQUE](/docs/security/authentication/). It never leaves your device either; OPAQUE only proves you know it.

### Why two secrets

The **Secret Key** is generated on your device, kept on your signed-in devices and in your [Recovery Kit](/docs/getting-started/recovery-kit/), and never sent to the server. It looks like:

```text
OP1-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXX
```

That's a version prefix plus 128 random bits as 26 Crockford base32 characters. When you type it, case, spaces and dashes don't matter, and look-alikes such as `O` and `0` are read the same. If the server database leaks, an attacker has the OPAQUE records and wrapped keys but not the Secret Key, and 128 random bits can't be brute-forced. So even a weak master password is safe against a server breach. 1Password uses the same two-secret approach.

### Why per-item keys

Each item has its own random key, wrapped by its vault's key. An item can be shared or moved by re-wrapping one small key instead of re-encrypting the whole vault. Removing someone from a shared vault re-wraps item keys under a new vault key.

Attachments hang off the item key in the same way: each file has its own random key, wrapped by the item key and kept in the item's encrypted details. A key rotation re-wraps item keys only, so files stay readable without being downloaded or encrypted again.

## Ciphertext format

```text
version (1 byte, 0x01) ‖ key_id (16 bytes) ‖ nonce (24 bytes) ‖ ciphertext ‖ tag (16 bytes)
```

Encoded as base64url without padding in JSON. `key_id` is the first 16 bytes of `SHA-256("octapass/v1/keyid" ‖ key)`, so an app can tell which key a ciphertext needs without trying to decrypt it.

**Associated data** binds every ciphertext to where it belongs: `"octapass/v1|"` followed by a context.

| Context | What's inside | Encrypted with |
|---|---|---|
| `ask` | Account key | AUK |
| `recovery` | Account key | Recovery code |
| `privkeys` | X25519 and Ed25519 private keys | Account key |
| `vaultkey:<vault id>` | Vault key | Account key |
| `itemkey:<vault id>:<item id>` | Item key | Vault key |
| `item:<vault id>:<item id>:overview` | Title, type, URLs, tags | Item key |
| `item:<vault id>:<item id>:details` | Everything else | Item key |
| `attachmentkey:<vault id>:<item id>:<attachment id>` | File key | Item key |
| `attachment:<vault id>:<item id>:<attachment id>` | Every chunk of the file | File key |
| `service-account-name:<vault id>:<service account id>` | A service account's name | Its creator's account key |
| `audit-detail:<account id>` | A security log entry only you can read | Account key |

Decryption fails if the server moves an encrypted key, field or file into another item or vault.

### Files

Attachments are encrypted a chunk at a time, so neither the app nor the server needs a whole file in memory:

```text
file    = header ‖ chunk_0 ‖ … ‖ chunk_n
header  = version (0x01) ‖ key_id (16 bytes) ‖ nonce prefix (19 random bytes)
chunk_i = XChaCha20-Poly1305(file key, nonce = prefix ‖ i (4 bytes) ‖ last (1 byte), associated data = "octapass/v1|attachment:…")
```

Each chunk holds 64 KiB of the file, except the last, which holds the rest and is the only one marked as last. A file that was cut short, had chunks dropped, reordered or added, or was moved to another item fails to decrypt, and the apps never show part of one. Encryption adds 52 bytes plus 16 per 64 KiB. Vault and item ids are UUIDs, so they can't contain the `:` separator. Each item also stores a `schemaVersion` inside its encrypted overview and details.

### Files you encrypt

`octapass encrypt` writes the [age v1 format](https://age-encryption.org/v1), through the `age` crate. Recipients are X25519 keys (`age1…`); passphrases use age's scrypt recipient. Folders are a tar archive inside age, and a file is only trusted to the end of the last chunk that checked out, so output takes its name only when it's whole.

- **Your file key** is an age key derived from your account's X25519 private key: `HKDF-SHA256(ikm = private key, salt = "", info = "octapass/v1/age-identity")`. Every device derives the same one. HKDF can't be run backwards, so exporting it doesn't reveal the account key.
- **Another user's key** is their published account X25519 key, in age's encoding. It needs nothing new from the server. As with sharing, it's as trustworthy as the fingerprint you compared. Their private key opens shared vaults too, so it's never exported.
- age's X25519 stanza and our sealed box use different HKDF `info` labels (`age-encryption.org/v1/X25519`, `octapass/v1/seal`), so neither can open the other's output.

### Octa Pass Safe

```text
safe key (32 random bytes, in a vault item)
 ├─ HKDF(salt = safe id, info = "octapass/v1/safe/records") ─► record key
 └─ HKDF(salt = safe id, info = "octapass/v1/safe/state")   ─► state key

record blob  = envelope(record key, padded(JSON record),
                        aad = "octapass/v1|saferecord:<safeId>:<blobId>")
record       = { object, rev, prev, parent, name, kind, size, modified, content, fileKey }
padded       = length (u32) ‖ JSON ‖ zeros to a multiple of 512 bytes

content blob = header ‖ chunk_0 ‖ … ‖ chunk_n, the attachment format above, with
               aad = "octapass/v1|safecontent:<safeId>:<objectId>:<blobId>"
```

Blobs are named by random UUIDs and never rewritten: a change writes new blobs under a new file key and nonce prefix, so no nonce is reused. A record names its content blob, and that blob's associated data names the object, so a record can't be paired with another file's content or an old one. Record blob ids start with `0x4d`, content ids with `0x43`, so a device can fetch records first.

Writes in progress are sealed chunk by chunk in an unnamed temporary file, under a key that exists only in memory, and re-sealed as a new content blob when flushed.

A synced Safe's blobs are stored as attachments of its vault item, which that item's details don't list. Vectors: `crates/octapass-core/tests/vectors/safe.json`.

## Service accounts

A [service account](/docs/features/service-accounts/) is a vault member that isn't a person. Its token holds a random 256-bit root that's never sent to the server. Two keys come from it:

```text
encryption key = X25519(HKDF-SHA256(root, salt = service account id, info = "octapass/v1/service-account/encryption"))
signing key    = Ed25519(HKDF-SHA256(root, salt = service account id, info = "octapass/v1/service-account/signing"))
token          = "opsa1_" + base64url(0x01 ‖ id (16) ‖ vault id (16) ‖ root (32) ‖ creator's public signing key (32) ‖ URL length (2, big-endian) ‖ server URL ‖ checksum (4))
```

The vault key reaches it as an ordinary signed grant, sealed to the X25519 key, exactly as for a member. The grant is checked against the creator's key **in the token**, never one the server names. To sign in, it signs a single-use challenge:

```text
"octapass/v1/service-account-auth" ‖ 0x00 ‖ for each of id, challenge: length (4, big-endian) ‖ UTF-8 bytes
```

The checksum is the first 4 bytes of SHA-256 over everything before it. It catches damaged copies and protects nothing.

## Recovery code

The recovery code is 256 random bits plus a 16-bit checksum, shown as 55 characters in 11 groups of 5. The checksum catches typos. It wraps the account key through `HKDF-SHA256(ikm = code, info = "octapass/v1/recovery")`. See [account recovery](/docs/security/account-recovery/).

## Device unlock in the web vault

The web vault can unlock with your device's own lock (Touch ID, Face ID, Windows Hello or the device passcode) through a passkey with the WebAuthn PRF extension. The passkey gives a 32-byte secret that only works on that device after it checks it's you. The vault turns it into a device key with `HKDF-SHA256(ikm = PRF output, salt = 16 random bytes, info = "octapass/v1/device-unlock")` and wraps your account key with it (context `device-unlock`). The wrapped copy stays in that browser and is never sent to the server. You still need your master password at least every 14 days.

## Stay unlocked

With [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in) on, the apps wrap your account key the same way (context `device-unlock`) under a random 32-byte secret kept where your device's own lock guards it but nothing asks for it: on iPhone a Keychain item that exists only while the phone has a passcode, on Android a Keystore key usable only while the phone is unlocked, on a Mac a Keychain item for the app, on Windows the system's data protection for your user, on Linux the Secret Service keyring. The browser extension keeps nothing on disk. Changing your master password, rotating your Secret Key or signing out deletes it, and the 14-day master password check still applies.

## Test vectors

Deterministic test vectors for the key derivation, Secret Key, recovery code, ciphertext envelope, attachment files, OPAQUE messages, device unlock, a service account and a complete account are in [`crates/octapass-core/tests/vectors`](https://github.com/octap-app/octapass/tree/main/crates/octapass-core/tests/vectors). Other implementations can use them to check that they interoperate.

## Locking

Locking zeroes the account key and every key derived from it in memory, and closes the decrypted search index.

## Related

- [Authentication](/docs/security/authentication/)
- [Account recovery](/docs/security/account-recovery/)
- [Threat model](/docs/security/threat-model/)
