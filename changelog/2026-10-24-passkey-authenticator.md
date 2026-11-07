---
title: The passkey authenticator in the core
date: 2026-10-24
summary: The Octa Pass core can now create passkeys and sign in with them, checked against independent WebAuthn verifiers. The browser extension will put it in front of websites.
tags: [core, security]
---

Octa Pass passkeys are ordinary encrypted items, so the authenticator lives in the shared Rust core, where every app can use it. It's built and tested; the browser extension that answers websites with it comes next.

## What it does

- **Creates passkeys** with ES256 (P-256), or EdDSA (Ed25519) when the site prefers it. Each passkey has a random 16-byte credential ID and the Octa Pass AAGUID (`c9a07734-1d0b-4c72-8ff5-45e0daa2064f`), with attestation `none`.
- **Signs in** with the passkey you pick. Passkeys sync, so they're reported as backed up and the signature counter stays 0.
- **Refuses the wrong site.** A page can only use a passkey for its own domain or a parent domain it could register: `login.example.com` can use `example.com`, but no page can use `co.uk` or `github.io` (checked against the Public Suffix List). Only `https` pages count (`http://localhost` for development), and a site inside another site's frame needs your permission first.
- **Stores passkeys inside logins.** A new passkey goes into the login for the site, or a new login named after it. The private key is kept only in the login's encrypted details, as a standard PKCS#8 key, and the passkey calls never hand it to JavaScript.
- **Moves passkeys** to and from the FIDO Credential Exchange Format (CXF), one passkey at a time, ready for the importers and exporters.

## How it's tested

Every passkey the core creates is checked by a relying-party verifier written from the WebAuthn specification with separate CBOR and COSE parsers, and, through WebAssembly, by Node's OpenSSL. Test vectors for both algorithms are in `crates/octapass-core/tests/vectors/passkey.json`. See [passkeys](/docs/features/passkeys/) for what websites see.
