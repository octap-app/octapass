---
title: Eleven features merged into one branch
date: 2026-11-03
summary: Health checks, vault features, key rotation, post-quantum sharing and the key log, organisations, Connect and service accounts, CLI and Git, the developer toolkit, local mode and native parity now live together, with the places where they met made consistent.
tags: [security, core, server, extension, desktop, mobile, cli]
---

The features from the 2 November entries were built side by side and are now merged into one branch for review. Where two of them met, the stricter rule now applies to both:

- **Organisation access is checked against the [key log](/docs/security/post-quantum-and-key-log/)** and sealed with post-quantum keys where the person has them, like every other share.
- **Renewing an emergency contact's key and turning on organiser recovery** check the key log and use post-quantum keys too.
- **Vault key rotations** keep the vault's service accounts working and check every member against the key log.
- **Version history** follows an organisation's two-step policy, like the rest of the vault.
- **The key log's background check** stops when the vault locks, so it can't sign you out while you unlock again.
- **The iPhone and Android apps** say where to sign in when an organisation requires single sign-on, which they can't do yet.

The server's new database migrations are numbered 0009 to 0013. Nothing had been released with the earlier numbers.
