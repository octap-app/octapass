---
title: The octapass command-line tool (preview)
date: 2026-10-24
summary: A native octapass CLI reads items and one-time codes, generates passwords, passes secrets to scripts with octapass:// references, and imports and exports, with a session kept in the OS keyring.
tags: [cli, security]
---

`octapass` is a native Rust binary in `apps/cli`, on the same core and sync code as the desktop app. Everything is decrypted on your computer, and an encrypted copy of your vault lets it read items offline.

- `octapass login`, `unlock`, `lock`, `logout` and `status`. Unlocking keeps a random session key in the OS keyring (macOS Keychain, Windows Credential Manager, the Secret Service on Linux) and locks again after 30 minutes without a command. The master password is never stored.
- `octapass list`, `get`, `totp` and `generate`. Secrets are printed only when you ask for them, with a warning when that's in a terminal.
- `octapass read octapass://Personal/Postgres/password` and `octapass run --env-file .env.octapass -- npm start`, which hands secrets to the command and nothing else.
- `octapass import` for the same browser, Bitwarden, 1Password, LastPass, CSV and authenticator files as the web vault, and `octapass export --format json|csv`, which asks for your master password again.
- `--json`, `--password-stdin` and stable exit codes for scripts.

There are no released builds yet: install it with `cargo install --path apps/cli`. See the [CLI docs](/docs/platforms/cli/).
