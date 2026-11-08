---
title: Breach checks
description: How Octa Pass checks your passwords against known data breaches with k-anonymity and padding so no password leaves your device, plus opt-in email breach alerts.
status: in-progress
sidebar:
  order: 7
---

:::note[In progress]
Password breach checks work in the web vault, the browser extension and the desktop and phone apps. They go straight from your device to Have I Been Pwned: the proxy through your server is planned. Email breach alerts are built and off by default; they need an HIBP key on the server.
:::
## Breached passwords

Octa Pass uses the Have I Been Pwned **Pwned Passwords** range API with k-anonymity:

1. Your device computes the SHA-1 hash of the password.
2. It sends only the **first 5 hex characters** of the hash, with the `Add-Padding: true` header so the response size doesn't leak anything.
3. The response lists hundreds of hash suffixes that share that prefix, with breach counts.
4. Your device checks whether its own suffix is in the list.

The password and its full hash never leave your device. The request goes straight from your device to `api.pwnedpasswords.com`, so HIBP sees your IP address and the 5-character prefix, and nothing else. A proxy through your Octa Pass server, so HIBP doesn't see your IP address, is planned.

Results appear in the [security dashboard](/docs/features/security-dashboard/).

## Email breach alerts (opt-in)

There is no public k-anonymity search for email addresses, so this check can't work the way the password check does: **the address itself has to leave your device.** That's why it's off until you turn it on, and why the app says what it sends before you do. Turning it on is a choice for the whole account, on all your devices.

While it's on, at most once a day or when you ask:

1. Your device sends your account email and your [masked email](/docs/features/masked-email/) aliases to your Octa Pass server, one at a time, each in the body of a signed-in request (`POST /v1/health/breach-email`), so they stay out of URLs and access logs.
2. The server asks the [Have I Been Pwned](https://haveibeenpwned.com) breach API about that address, with the server's API key.
3. Your device stores what came back in your encrypted vault, and shows it in the [security dashboard](/docs/features/security-dashboard/#email-breach-alerts).

**Who sees what:**

- **Your server** sees each address while it handles the request. It doesn't write it to the database, to logs or to a cache. It can't check that an alias is yours, and it does learn, for that moment, that your account asked about it. That's a real cost for aliases, whose purpose is that they can't be tied to you.
- **Have I Been Pwned** sees each address and your server's IP address, not yours. It can't tell which account asked.
- **Nobody else.** Breach results are encrypted in your vault. Turning alerts off deletes them.

Each account can make 60 lookups, refilling one every 30 minutes, and one check sends at most 50 addresses. This keeps the feature from being used to look up other people's addresses, though it can't rule that out for a few addresses a day.

Recovery emails that aren't your account email or an alias aren't sent; see [recovery info](/docs/features/recovery-info/#dashboard-checks). Breach data comes from Have I Been Pwned.
