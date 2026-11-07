---
title: Counter-based one-time codes work
date: 2026-11-02
summary: HOTP codes are now real codes with a Next code button, counter sync and imports, instead of hidden fields.
tags: [core, extension, desktop, mobile]
---

Octa Pass now handles HOTP (RFC 4226) codes. A login with one shows **Next code**, which saves the moved counter before showing the code, and **Change counter** for when a site falls out of step. Counters sync, and two devices using a code at once never get the same one.

Imports from otpauth lists, Google Authenticator, Aegis, 2FAS, andOTP, Ente Auth, Raivo and KeePass now keep HOTP as a working code. Codes imported earlier stay in a hidden field; [copy the link into the code field](/docs/features/totp/#counter-based-codes-hotp) to use them.

The browser extension fills them. System AutoFill on Mac, iPhone and Android, auto-type and quick access don't, because they can't save the counter.
