---
title: Glossary
description: Definitions of the terms used in the Octa Pass documentation, from Account Unlock Key and Secret Key to OPAQUE, passkeys, TOTP, CXF and k-anonymity.
status: stable
sidebar:
  order: 2
---

| Term | Meaning |
|---|---|
| **Account Symmetric Key (ASK)** | A random 256-bit key that unlocks your private keys and personal vault keys. It's stored on the server only in wrapped (encrypted) form. |
| **Account Unlock Key (AUK)** | The key derived from your master password and Secret Key. It unwraps your ASK. |
| **MIT** | The MIT License, a short permissive open-source licence. Octa Pass is published under it. |
| **Argon2id** | A memory-hard password hashing function that makes guessing master passwords slow and expensive. |
| **Associated data** | Unencrypted context bound to a ciphertext. Decryption fails if the ciphertext is moved somewhere else. |
| **Auto-type** | Typing a username and password into the focused app with simulated keystrokes, used where no autofill API exists. |
| **CXF / CXP** | The FIDO Alliance's Credential Exchange Format and Protocol: standards for moving passwords and passkeys between managers. |
| **Emergency access** | Letting a trusted contact access your vault after a waiting period you control. |
| **Item key** | A random key for one item, wrapped by its vault key. |
| **k-anonymity** | Sending only a short hash prefix that matches many entries, so the server can't tell which one you're checking. |
| **Masked email** | A forwarding alias that hides your real email address from a website. |
| **Master password** | The password you remember. It's never sent to the server. |
| **OPAQUE** | A password-authenticated key exchange (RFC 9807) that lets you sign in without the server ever learning your password. |
| **Passkey** | A WebAuthn key pair that replaces a password for one site. It can't be phished. |
| **PRF extension** | A WebAuthn extension that lets a passkey produce a secret, which can be used to unlock a vault. |
| **Public Suffix List (PSL)** | A list of domain suffixes (like `co.uk`) used to work out a site's registrable domain for safe matching. |
| **Recovery code** | A 256-bit key shown once at sign-up that can restore access if you forget your master password. |
| **Recovery Kit** | A PDF made on your device with your Secret Key, recovery code and account details. |
| **Recovery map** | A view that groups your accounts by the email or phone that can reset them. |
| **Secret Key** | A random 128-bit key (`OP1-…`) combined with your master password. It's never sent to the server. |
| **TOTP** | Time-based one-time passwords (RFC 6238): the 6-digit codes from authenticator apps. |
| **Vault key** | A random key for a vault, wrapped for each member who has access. |
| **XChaCha20-Poly1305** | The authenticated encryption algorithm Octa Pass uses for all vault data. |
| **Zero-knowledge** | A design where the service provider can't read your data, because only you hold the keys. |
