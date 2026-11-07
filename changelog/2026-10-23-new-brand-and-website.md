---
title: A new brand and a redesigned website
date: 2026-10-23
summary: Octa Pass has a new OP monogram logo, a trust-blue and open-source-green palette, and a product-style website with a live encryption demo.
tags: [website, decision]
---

## New brand

- **Logo:** an **O** ring, open at the bottom, around a **P** whose stem passes out through the opening, with a keyhole in the P. *Open* and *Pass* in one mark. It comes in a gradient mark, a one-colour mark and an app-icon tile.
- **Colours:** trust blue (`#2456F0`) and freedom green (`#10B77F`, the colour of open source), meeting in one signature gradient.
- **Type:** Mona Sans for everything, with its width axis for headlines, and Monaspace Neon for passwords, codes and ciphertext. Both are self-hosted.
- **Wordmark:** OctaPass, with "Open" light and "Pass" bold.

See `brand/README.md` for the full guide.

## Redesigned website

- A product page: an app window and an iPhone passkey sheet, drawn in HTML and CSS with a live one-time code.
- "We store it. We can't read it.": the same login shown as you see it and as the server stores it. The ciphertext is made in your browser, and the login seals itself as you scroll to it.
- A bento grid covering passkeys, codes, autofill, breach checks, masked email, recovery info, cards and import.
- The docs, changelog and 404 page use the same theme.

## Clarified: breach checks

People asked how Octa Pass can check passwords against data breaches if it can't read them. The check runs on your device: it hashes the password, sends only the first 5 characters of the hash, and compares the hundreds of matches it gets back locally. See [breach checks](/docs/security/breach-checks/).
