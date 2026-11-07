---
title: Each website once, and a warning when a password is reused
date: 2026-11-05
summary: A login no longer lists the same site two or three times after importing from several apps, and its page now says when its password is also on other logins.
tags: [core, extension, desktop, mobile]
---

**Each website once.** Chrome, Apple Passwords and Firefox each write a site a little differently: `https://example.com`, `https://example.com/`, `https://example.com/login`. Importing from all three left a login showing "example.com" several times. Now those count as one website:

- Importing again keeps the address your vault already has, with its match rule, and adds only the sites that are new.
- The login's page lists each website once, in the web vault, the desktop app, the extension and the iPhone, iPad and Android apps.
- Saving a login in the editor drops the repeats. Logins you don't edit aren't rewritten.
- Saving a login from autofill on the phones doesn't add a site the login already has.

Two addresses are one website when autofill would offer the login on the same pages for both. By default that's the same host, whatever the `http` or `https`, port, path or leading `www.`. See [one website, listed once](/docs/features/item-types/#one-website-listed-once).

**Reused passwords, on the login.** A login whose password is also used on other logins now says so at the top of its page: "Password used on 3 other logins". **See them** lists those logins, each with **Change password**, which opens the site's change-password page. It uses the report Health already made, and a group you dismissed in Health shows no warning. See [the security dashboard](/docs/features/security-dashboard/#on-the-login-itself).

The rule is in `plans/07-import-export.md` and the warning in `plans/06-health-sharing-aliases.md`.
