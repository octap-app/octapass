---
title: The SSH agent asks once, then not for 15 minutes
date: 2026-11-09
summary: The SSH agent no longer asks for your fingerprint on every signature. One approval lasts 15 minutes or until the vault locks, and a locked vault asks you to unlock it.
tags: [decision, security, desktop]
---

The SSH agent in the Mac app and in the Windows and Linux app asked for Touch ID, Windows Hello or your password before every signature, even with the vault open. A `git pull`, a `git push` and an `ssh` in a row meant three prompts.

Now:

- **Keys are always offered.** While the vault is unlocked, `ssh-add -l` lists them without asking.
- **One approval lasts 15 minutes.** The first signature asks, naming the key and the program. Signatures in the next 15 minutes don't ask. Locking the vault ends the 15 minutes early.
- **A locked vault asks to unlock.** A request while the vault is locked asks for your fingerprint or face if device unlock is on. Otherwise the Octa Pass window comes forward and the request waits for your master password. That unlock counts as your approval, so you aren't asked twice.

The trade-off: for those 15 minutes, a program running as you can use the agent without a prompt. It still can't read your keys. The decision is recorded in [plan 03](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md) and [plan 16](https://github.com/octapass/octapass/blob/main/plans/16-developer-toolkit-and-files.md). See [SSH agent](/docs/features/ssh-keys/#ssh-agent).
