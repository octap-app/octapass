---
title: Not just a password manager
date: 2026-11-08
summary: The website, README and docs now say what Octa Pass is, one encrypted place for everything sensitive, and show the SSH keys, secrets, IDs, wallets and Safes that sit beside your passwords.
tags: [decision, website, docs]
---

Octa Pass does everything a password manager does, but it has grown into more than that, and the old line ("the password manager only you can open") hid most of it. The new one is **everything sensitive, in one place only you can open.**

- **Home page.** The headline cycles through what you'd keep: passwords, SSH keys, a passport, `.env` files, a seed phrase, tax returns. A new section lays out all 22 kinds of item as a honeycomb you can filter (everyday, money, identity, developers, files). A developer band shows the SSH agent asking before git signs, `octapass run` and service accounts. A Safe you can lock shows its file names turning into the random blob names that are really on disk. The app window in the hero lists every category, with icons. The nav gets a **What it keeps** link. In English and Arabic.
- **README.** A new banner, a tall "Not just a password manager" image with every kind of item, and an image for developers. They're made from HTML by `brand/source/render_headers.py`, which uses the website's icons.
- **Docs and plans.** The docs home and overview list everything Octa Pass keeps, grouped, with the out-of-date "planned" line removed. The positioning in [plan 01](https://github.com/octapass/octapass/blob/main/plans/01-product-spec.md#positioning) and the brand guide now explain when to say "password manager": where people search for one, never as the whole description.
