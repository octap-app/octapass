---
title: The developer toolkit
date: 2026-11-02
summary: Make and read TLS certificates, keys, JWTs, hashes and encodings on your own device, from the CLI, the web vault and the desktop app, with Certificate and Key items in the vault.
tags: [core, cli, desktop, extension, mobile, security]
---

Octa Pass now has a Tools section and matching `octapass` commands. One implementation in the Rust core does the work everywhere, on your device, and results save to the vault as encrypted items.

- **Certificates:** self-signed certificates, a private local CA you can trust on your machine, CSRs, RSA, ECDSA and Ed25519 keys, and PEM, DER and PKCS#12 files. A new local CA can only issue for private names such as `localhost` and `*.test`, so a stolen CA key can't impersonate a public site.
- **ACME:** certificates from Let's Encrypt, ZeroSSL and other CAs with HTTP-01 and DNS-01, and renewal reminders.
- **Keys:** OpenPGP and age keys, JWT signing keys with JWK and JWKS, and conversion between PEM, DER, JWK, OpenSSH, PKCS#8 and PKCS#1.
- **Tokens:** read, sign and verify JWTs, decrypt JWE. `alg: none` is never valid, and a public key can't be replayed as an HMAC secret.
- **Everyday tools:** hashes and HMAC for text and files, encodings with auto-detection, random data, UUID v4 and v7, ULID, NanoID, API keys, password hashes with verify, and new TOTP secrets.

Inspectors work offline. The only network use is one you ask for: reading a live `host:443`, fetching a JWKS URL, or talking to an ACME CA, and each says so first. Private keys stay encrypted in the vault and are shown or exported only after you confirm it's you. See [Developer toolkit](/docs/features/developer-toolkit/).
