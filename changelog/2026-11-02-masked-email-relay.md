---
title: The masked email relay is built, and off by default
date: 2026-11-02
summary: Octa Pass now has its own mail forwarder for masked email, for servers that turn it on. It stores no messages, and the hosted service doesn't run it.
tags: [server, security]
---

`octapass-relay` is a new, separate service that gives a server its own masked email: random aliases that forward to the account's verified email, with replies going back out through the alias. See [the masked email relay](/docs/self-hosting/relay/).

- **No queue.** A message is forwarded while the sender is still connected, and accepted only once the outgoing provider has taken it. Messages never reach a disk or a log.
- **The real address stays private both ways.** Replies are rebuilt from a short list of headers, and bounces are counted, never passed on.
- **Abuse handling.** SPF, DKIM, DMARC and ARC checks, rate limits, per-alias blocks, and automatic pauses after bounces or spam reports, with one email saying so.

It is **off by default**, and **the hosted service doesn't run it**. It's been tested with real SMTP on one machine, but not yet with real DNS, a real mail provider or a real inbox. Running it publicly needs decisions on the domain, the provider and abuse handling first.

Your vault isn't affected. Email isn't end-to-end encrypted, though, so on a server with the relay, mail is readable by the relay while it's forwarded, and it keeps the addresses of people who wrote to your aliases. [What the server sees](/docs/security/what-the-server-sees/) has the details.
