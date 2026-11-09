---
title: The menu bar and tray icon come back after a force quit
date: 2026-11-09
summary: If the desktop app is force quit or crashes, it starts again by itself in the background, with its menu bar or tray icon and no window. Quitting it from the icon's menu stops it.
tags: [desktop]
---

Octa Pass keeps running with its window closed, so quick access, the browser extension, the CLI and the SSH agent keep working. But a force quit or a crash took it away until you opened it again, menu bar or tray icon and all.

Now it comes back, the way VPN and container apps do:

- **Force quit or crashed:** Octa Pass starts again a couple of seconds later, in the background. The icon is back, the window stays closed and the vault is locked, unless it stays unlocked.
- **Quit on purpose:** **Quit Octa Pass** in the icon's menu stops it until you next sign in or open it. On a Mac, Cmd+Q, Quit in the Dock and logging out count as quitting too.
- **Crash loops:** if it keeps ending soon after it starts, it stops trying after three times.

On a Mac a small helper inside the app, **Octa Pass Watchdog**, does this while Octa Pass runs. It has no window, no access to your vault and no network. On Windows and Linux the app watches itself with a second copy of its own program. See [running in the background](/docs/platforms/desktop/#running-in-the-background).

The Windows and Linux part hasn't been tried on those systems yet.
