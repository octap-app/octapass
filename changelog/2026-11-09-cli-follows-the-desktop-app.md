---
title: The CLI uses the desktop app's account, and installs with one command
date: 2026-11-09
summary: With the Octa Pass app on your computer, the CLI needs no sign-in of its own and is unlocked whenever the app is. On its own, it installs with one curl command.
tags: [decision, security, cli, desktop, server, website]
---

**The CLI follows the desktop app.** While the Mac app or the Windows and Linux app is running:

- A CLI that isn't signed in uses the app's account. The app makes it a session of its own on the server, so it shows in your device list as "Octa Pass CLI" and you get a new sign-in email. `octapass link` does it on purpose. A CLI signed in to its own account keeps it.
- While the app is unlocked, `octapass` commands run without asking. Before, the first command in each terminal asked for Touch ID or Windows Hello, and the approval lasted 30 idle minutes.
- While the app is locked, a command asks for your fingerprint or face if device unlock is on, which unlocks the app too. `octapass lock` locks the app as well.

The trade-off: while the app is unlocked, a program running as you can read your secrets through the CLI without a prompt. Lock the app, or set `OCTAPASS_NO_DESKTOP=1`, to stop that. The decision is in [plan 03](https://github.com/octapass/octapass/blob/main/plans/03-security-model.md). The server has a new endpoint, `POST /v1/devices/link`, for the new device session.

**One-command install.** On macOS and Linux, `curl -fsSL https://octap.app/install.sh | sh`. On Windows, `irm https://octap.app/install.ps1 | iex`. The script downloads the release for your computer, checks it against the release's `SHA256SUMS`, and installs to your home folder without administrator rights. Until releases are published, it builds the CLI with `cargo` when Rust is installed. Without the desktop app, the CLI tells you what installing it adds.

See [Using the desktop app's account](/docs/platforms/cli/#using-the-desktop-apps-account) and [Install](/docs/platforms/cli/#install).
