---
title: Desktop app preview (macOS, Windows, Linux)
date: 2026-10-24
summary: A Tauri desktop app shows the web vault on a native vault, with Touch ID unlock, quick access and browser integration.
tags: [desktop, security]
---

The Octa Pass desktop app is taking shape in `apps/desktop` (Tauri 2). It shows the web vault's screens, but the keys stay in the app's native process: it links the Rust core directly and syncs with the server itself.

- Sign up, sign in, lock and unlock, items and sync against your server, offline unlock from an encrypted local copy.
- Unlock with Touch ID or your Mac password; Windows Hello and Linux polkit are built and tested, not yet tried on those systems.
- Quick access on ⌘⇧Space (Ctrl+Shift+Space): search and copy a username, password or one-time code. The clipboard clears after 30 seconds.
- A native messaging host so the browser extension can unlock through the app (Browser menu → Connect browser extension).

It's a preview: there are no signed builds yet.
