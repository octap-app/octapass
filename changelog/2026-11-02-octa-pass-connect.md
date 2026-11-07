---
title: Octa Pass Connect and live API tokens
date: 2026-11-02
summary: A local helper hands approved programs a secret by reference, every hand-out goes in your security log, and API credentials can hold a live OAuth2 token.
tags: [cli, desktop, security, docs]
---

[Octa Pass Connect](/docs/features/connect/) is one generic way for a program on your computer to ask for a secret by `octapass://` reference. It listens on a local socket or loopback only, each program has to be approved, and it never unlocks anything. Each secret it hands out is recorded before it leaves, sealed so that only you can read which one and to what. The [API](/docs/developers/connect-api/) is plain HTTP, so anything can use it.

API credential items can now hold an OAuth2 client, with the client-credentials or refresh-token flow. The field `accessToken` is always a current bearer token.

The CLI also speaks three other tools' formats: AWS `credential_process`, the `kubectl` exec plugin and the Docker credential helper. See [the CLI docs](/docs/platforms/cli/#cloud-and-devops).
