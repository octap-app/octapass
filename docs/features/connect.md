---
title: Octa Pass Connect
description: A local helper that gives approved programs a secret by octapass:// reference, with per-client approval, a session token, and every secret recorded in your security log.
status: in-progress
sidebar:
  order: 31
---

:::note[In progress]
Connect works in the CLI today. In the desktop app, it's built but has only been compiled, not exercised on a real desktop.
:::

**Octa Pass Connect** is a helper on your own computer. A program asks it for a secret by reference, such as `octapass://Work/Stripe/password`, instead of you pasting the value somewhere. It's one generic interface: there's no integration for any one product. API clients such as Postman, Insomnia or Bruno use it through their scripts or environment variables, and anything with an HTTP client can use the [Connect API](/docs/developers/connect-api/).

For tools that read environment variables or files, you may not need Connect at all: [`octapass run` and `octapass inject`](/docs/platforms/cli/#secrets-in-scripts-and-apps) do the job.

## Start it

```bash
octapass unlock
octapass connect serve
```

It stays in the foreground and asks for approvals in that terminal. In the desktop app, turn on **Settings → Octa Pass Connect**. It's off by default, and approvals are a system dialog. One Connect runs per user.

## Approving a program

The first time a program asks, you see the name it gave and, where the system can tell, the program that actually connected. **A name is only a claim**, so check the program.

Approving gives it a token for 30 days. On a socket the token only works from that same program.

```bash
octapass connect clients          # who's approved
octapass connect revoke <id>      # take it back
```

A tool that can't wait for a prompt can be approved from your terminal, which asks for your master password:

```bash
octapass connect approve --name "Nightly report"
```

## What protects you

- **Only this computer.** It listens on a socket only you can open, or `127.0.0.1` on Windows or with `--port`. Web pages can't reach it: requests with an `Origin` header, or a `Host` that isn't loopback, are refused.
- **Only while unlocked.** Connect never unlocks anything. `octapass lock` or the idle timeout stop it at once, and its reads don't extend the timeout, so a tool that polls can't keep your vault open.
- **Everything recorded.** Each secret handed out is written to a queue on your device, sealed so only you can read it, *before* it's handed out, then sent to your [security log](/docs/security/overview/). The server stores a blob: it learns that a secret was handed out and when, not which one or to what. If the entry can't be written, the secret isn't handed out.

It's a record, not a wall: a program you approved can do what it likes with the secrets you let it read, and malware running as you is out of scope, as for every password manager.

## Live API tokens

An API credential item can hold an OAuth2 client. Connect and the CLI then hand out a current bearer token at its `accessToken` field:

```bash
octapass oauth create "Billing API" --flow client-credentials \
  --token-url https://auth.example.com/oauth/token --client-id abc --scope "read write"
octapass read "octapass://Work/Billing API/accessToken"
octapass oauth show "Billing API"     # claims and expiry, not the token
```

Both the client-credentials and refresh-token flows work. The token is cached, encrypted in the item, until a minute before it expires. A new refresh token from the provider replaces the old one.

The token URL is the only network use. It must be `https` (`http` only on this computer), and redirects are never followed. The server never sees any of it.
