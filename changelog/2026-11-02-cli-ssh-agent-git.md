---
title: The CLI edits items, and an SSH agent and Git signing arrive
date: 2026-11-02
summary: Create, edit and delete items and sign up from the terminal, hide secrets in `octapass run` output, unlock the CLI through the desktop app, serve SSH keys to ssh and Git with per-use approval, and sign commits with keys from your vault.
tags: [cli, desktop, security, core]
---

**In the [CLI](/docs/platforms/cli/):**

- `octapass create`, `edit`, `delete` and `restore`, and `octapass signup`.
- `octapass run` hides secrets in the command's output, also when they arrive in pieces. Interactive programs need `--no-masking`, because the output is then a pipe.
- A locked `octapass` can ask the running desktop app, which confirms with Touch ID or Windows Hello. Nothing is kept on disk, and locking the app locks the CLI too.
- `git-credential-octapass` gives Git the login for that exact host, and `octapass git setup` turns it on, with commit signing from SSH or OpenPGP keys in your vault.

**In the [desktop app](/docs/features/ssh-keys/#ssh-agent):** an SSH agent, off until you turn it on, serves your vault's keys to `ssh`, Git and IDEs and asks you for every use. The key editor reads keys from `~/.ssh` and can write them back. SSH keys can now be generated and imported in the desktop app.

**RSA:** the `rsa` crate's timing advisory (RUSTSEC-2023-0071) is still open, so Octa Pass signs RSA with `ring` instead, and never with SHA-1. RSA OpenPGP keys can't sign yet.
