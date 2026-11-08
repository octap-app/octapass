---
title: Security overview
description: How Octa Pass protects your vault with zero-knowledge, end-to-end encryption, a Secret Key, OPAQUE login and phishing-safe autofill, and how it is audited.
status: in-progress
sidebar:
  order: 1
---

:::note[Design document]
This section is the security design, and most of it is built. Nothing has had its external audit yet, post-quantum sharing and the key log haven't had the outside cryptographer's review, and the items listed under [not built yet](#not-built-yet) don't exist. Feedback is welcome: see [contributing](/docs/contributing/overview/).
:::

## Goals

1. **Confidentiality against the server.** Someone with full access to the servers and database can't read vault contents or your master password. That includes the Octa Pass team, an attacker, or someone with a court order.
2. **Resistance to offline cracking.** A stolen database can't be brute-forced, even for weak master passwords.
3. **Integrity.** The server can't swap, forge or roll back items without clients noticing. Full rollback detection is planned for 1.0.
4. **Recovery without a backdoor.** Users who forget their password recover with something only they hold.
5. **Phishing-safe autofill.** Credentials go only to the site they belong to, and only when you ask.

## The design in brief

| Layer | What protects it | Read more |
|---|---|---|
| Your vault data | Encrypted on your device with XChaCha20-Poly1305, per-item keys | [Encryption](/docs/security/encryption/) |
| Your keys | Derived from your master password (Argon2id) **and** a 128-bit Secret Key | [Encryption](/docs/security/encryption/) |
| Signing in | OPAQUE (RFC 9807): your password never reaches the server | [Authentication](/docs/security/authentication/) |
| Forgotten password | Recovery code, Recovery Kit, emergency contacts | [Account recovery](/docs/security/account-recovery/) |
| Device unlock | Hardware-backed keys gated by your device's own lock | [Biometric unlock](/docs/features/biometric-unlock/) |
| Stay unlocked (on by default in the apps) | A key the device's own lock guards, with no prompt; revealing doesn't ask, exporting always does | [Stay unlocked](/docs/features/biometric-unlock/#stay-unlocked-while-youre-logged-in) |
| Autofill | Exact domain matching, user gesture required, clickjacking defences | [Autofill](/docs/features/autofill/#safety-rules) |
| Breach checks | k-anonymity: passwords never leave your device | [Breach checks](/docs/security/breach-checks/) |

## Being honest about limits

- **The server still sees some metadata**, such as your email, item counts and timestamps. The full list is in [what the server sees](/docs/security/what-the-server-sees/).
- **The web vault is the weakest client.** Its code is served by the server, so a compromised server could serve malicious code. For the highest assurance, use the signed apps and extensions once they're released. See the [threat model](/docs/security/threat-model/).
- **Malware on an unlocked device** can read what you can read. No password manager can fully prevent that.
- **If you lose your password, Secret Key and recovery code, and have no emergency contact, your data is gone.** That's the price of zero-knowledge.

## Security process

- A security review section is required in every change that touches cryptography, keys, authentication, sync or autofill.
- **External audit** of everything that ships in 1.0, with the full report published. It hasn't started.
- **Bug bounty** from the public beta. Until then, report issues privately as described in `SECURITY.md` (90-day coordinated disclosure).
- Fuzzing for importers, backups, share links, sealed keys, passkey requests, one-time code links and URL matching, every week in CI. Property tests for encryption envelopes.
- Published test vectors for the cryptographic constructions, so third-party clients can interoperate.

## Not built yet

These are part of the design and required for 1.0, but they don't exist today:

- Signed vault manifests, which let clients detect a server rolling items back
- Subresource Integrity and a check by the extension that the web vault's code is the published code
- Reproducible, signed builds and an SBOM for every release
- `cargo deny`, `cargo vet` and two-person release approval
- Proof-of-work after repeated failed sign-ins (rate limits are built)
- Encrypted device names
