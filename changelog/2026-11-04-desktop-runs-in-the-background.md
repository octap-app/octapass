---
title: The desktop app runs in the background
date: 2026-11-04
summary: The desktop app has an icon in the menu bar or system tray and opens when you sign in to the computer, so quick access and the browser extension are ready straight away. Both can be turned off.
tags: [desktop]
---

Closing the Octa Pass window never quit the app, but on Windows and Linux there was no way back to it except the quick access shortcut. Now:

- **An icon in the menu bar (macOS) or system tray (Windows, Linux)** shows your vault, opens quick access, locks Octa Pass or quits it.
- **Octa Pass opens when you sign in to the computer**, in the background and locked, so quick access, the browser extension, the SSH agent and AutoFill on the Mac work without opening it first.
- Opening Octa Pass again shows the copy that's already running instead of starting a second one.

Both are on by default. Turn either off in **Settings → Running in the background**, for that computer only; opening at login can also be turned off in the system's own startup settings. See [running in the background](/docs/platforms/desktop/#running-in-the-background).
