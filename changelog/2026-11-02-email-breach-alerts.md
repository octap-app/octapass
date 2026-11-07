---
title: Opt-in email breach alerts
date: 2026-11-02
summary: Health can tell you when your account email or aliases appear in a breach. It's off by default, because this is the one check that sends an address off your device.
tags: [security, server, core]
---

[Email breach alerts](/docs/security/breach-checks/#email-breach-alerts-opt-in) check your account email and masked email aliases against Have I Been Pwned, through your Octa Pass server.

There's no way to do this without sending the address, so it works differently from the password check:

- It's off until you turn it on, and the app says what's sent, and to whom, before you do.
- Your server handles each address in memory and keeps nothing. Results are stored in your encrypted vault, and turning alerts off deletes them.
- This does tell your server which aliases are yours. If that matters to you, leave it off.

Self-hosters: the feature exists only if you set `OCTAPASS_HIBP_API_KEY`, and it's off by default. See [configuration](/docs/self-hosting/configuration/#email-breach-alerts).
