---
title: The web vault now runs on the real crypto core and sync server
date: 2026-10-23
summary: Sign up, sync, lock, device unlock and account deletion in the web vault now use the Rust core in WebAssembly and a real Octa Pass server, and an end-to-end test checks that the server only ever stores ciphertext.
tags: [core, server, security]
---

The web vault preview no longer runs on a mock. Everything secret now happens in the Rust crypto core, compiled to WebAssembly and kept in a Web Worker, away from the page: Argon2id, OPAQUE sign-in, the account and vault keys, and encrypting each item before it's sent. The page only sees what it shows you.

- **Sign up and sign in** against an `octapass-server`, with email verification and your Recovery Kit. A new device asks for your Secret Key once.
- **Sync:** your vault is pulled when you unlock, then kept up to date when you come back to the tab, every 30 seconds while it's open, and after every change. If two devices edit the same item, nothing is lost: the second edit is saved as a conflicting copy.
- **Offline:** this browser keeps the encrypted records, so you can unlock and read your vault without a connection.
- **Device unlock** (Touch ID, Windows Hello, your device passcode) and **account deletion** work for real. Deleting your account removes it from the server and wipes this browser; your other devices wipe themselves the next time they connect.
- The crypto module the browser downloads is now about 790 KB instead of 3 MB. Password strength is checked on the page, so the web build leaves out the strength dictionaries.

An end-to-end test drives Chrome through an account's whole life and checks the server's database files for the item's title, website, username, password and note. None of them are there. It also checks that no table mentions the account after it's deleted.

Developers can run the whole stack with `pnpm --filter @octapass/web dev:stack`. See [development setup](/docs/contributing/development-setup/) and the integration notes in plan 11.
