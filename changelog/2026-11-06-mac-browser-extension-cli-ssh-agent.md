---
title: The Mac app works with the browser extension, the CLI and SSH
date: 2026-11-06
summary: The native Mac app unlocks the browser extension and the octapass CLI with Touch ID, and runs the SSH agent, as the Tauri app did.
tags: [desktop, extension, cli]
---

The native Mac app now does what the Tauri app did for your other tools, with the same checks:

- **Browser extension.** Settings → Browser extension → **Connect browser extension** lets the extension in Chrome, Edge, Brave, Chromium and Firefox unlock through the app, with Touch ID or your Mac's password.
- **CLI.** A locked `octapass` asks the running app, which asks you once per terminal, naming the program.
- **SSH agent.** Settings → SSH agent turns it on. The app is sandboxed, so the agent's socket is in its own folder; Settings shows the path and the `IdentityAgent` lines to add to `~/.ssh/config`. Every signature still asks you.

See [SSH keys](/docs/features/ssh-keys/#ssh-agent), [the CLI](/docs/platforms/cli/) and [plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md).
