---
title: Post-quantum sharing and a key log
date: 2026-11-02
summary: Shares are now sealed with hybrid X25519 + ML-KEM-768, and account keys go into an append-only log that clients check. Neither has had the outside cryptographer's review yet.
tags: [security, core, server]
---

Two additions to sharing, in the web vault, the desktop app, the CLI and the phone apps. See [plan 03](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md).

- **Hybrid sealing.** Keys shared with another account are sealed so they stay safe as long as either X25519 or ML-KEM-768 holds. Existing shares keep working, and stay classical until the vault's next key rotation.
- **A key log.** Account public keys go into an append-only log that clients check, so a server can't swap a key without leaving a trace for its owner. It supports comparing fingerprints and doesn't replace it. It can't yet catch a server that shows different people different logs: that needs independent witnesses.

The web vault and desktop app show each member as in the key log, not in it yet, or failing the check. The phone apps run the same checks but don't show them yet. Neither feature has had the outside cryptographer's review, so neither should be relied on yet. Details: [post-quantum sharing and the key log](/docs/security/post-quantum-and-key-log/).
