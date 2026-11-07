---
title: The Rust crypto core runs in the browser
date: 2026-10-23
summary: The Octa Pass crypto core is built. Key derivation, encryption, OPAQUE login and the vault tools are now in Rust and compiled to WebAssembly for the web vault.
tags: [core, security]
---

The encryption design from the [security docs](/docs/security/encryption/) is now real code. It's one Rust library that every Octa Pass app will share. The web vault runs it as WebAssembly inside a Web Worker, so keys never touch the page's JavaScript.

## What's built

- **Key derivation:** your master password goes through Argon2id (64 MiB, 3 iterations) and is combined with your 128-bit Secret Key into the key that unlocks your account. In WebAssembly an unlock takes about 0.2 seconds on a 2019 laptop.
- **Encryption:** every ciphertext is XChaCha20-Poly1305, tagged with a key id and bound to its place (account, vault, item, overview or details), so the server can't move encrypted data around.
- **Login without sending your password:** sign-up and sign-in use OPAQUE. Re-authentication before deleting your account uses the same protocol.
- **Device unlock:** the web vault can wrap your account key with a passkey's PRF secret, so Touch ID, Windows Hello or your device passcode can unlock it. That key never leaves the browser.
- **Recovery:** a 256-bit recovery code, 11 groups of 5 characters with a built-in typo check, can unlock your account if you forget your password.
- **Tools that run on your device:** TOTP codes (including Google Authenticator exports), a password and passphrase generator using the EFF wordlist, strength estimation, and the k-anonymity check for breached passwords.

## For developers

The formats are documented byte by byte in `crates/octapass-core/README.md`, and the web worker API in `crates/octapass-wasm/README.md`. Deterministic test vectors for every construction are in `crates/octapass-core/tests/vectors`, so other implementations can check that they interoperate.
