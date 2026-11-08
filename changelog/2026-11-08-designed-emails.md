---
title: Emails from the server are designed now
date: 2026-11-08
summary: Verification codes, new-device alerts and the other emails the server sends now come with a branded HTML version beside the plain text, with no remote images, tracking or links.
tags: [server]
---

Every email the sync server sends, from the verification code to the new-device and emergency access notices, now carries an HTML version next to the plain text. It has the Octa Pass logo, a short label for what the email is about, a clear heading, the code in large type when there is one, details like a new device's name and time in a small table, and the "if this wasn't you" advice set apart. It follows the reader's light or dark mode and fits a phone. Mail apps that only show text still get the same words.

Nothing in it reaches out: the logo travels inside the email instead of loading from a server, there are no tracking pixels, and there are no links, so the footer can say that Octa Pass emails never contain sign-in links. Names that people choose, like a family organiser's or a device's, are escaped, so they can't add anything to the email. See [plan 04](https://github.com/octapass/octapass/blob/main/plans/04-sync-server.md).

To look at every email in a browser, run `OCTAPASS_EMAIL_PREVIEW=/tmp/emails cargo test -p octapass-server email_previews -- --ignored` and open the files it writes.
