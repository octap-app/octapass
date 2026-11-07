---
title: Service accounts for CI and servers
date: 2026-11-02
summary: A token bound to one shared vault, read-only by default, revocable and logged, that lets a job read secrets without the server ever seeing them.
tags: [cli, server, security, core, docs]
---

[Service accounts](/docs/features/service-accounts/) let a CI job or a server read one shared vault with no person there. The token is a key made on your device and never sent to the server, so zero-knowledge holds: the runner decrypts for itself.

Each token works for one shared vault and is read-only unless you say otherwise. Every fetch appears in your security log, and revoking cuts it off at once and rotates the vault's key. There's a GitHub Action and a GitLab CI template in `integrations/`, and Terraform and Pulumi work through `octapass run`.

The design is in [plan 03](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md), and the format is in [Encryption](/docs/security/encryption/#service-accounts), with test vectors.
