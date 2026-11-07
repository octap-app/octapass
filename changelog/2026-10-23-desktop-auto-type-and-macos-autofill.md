---
title: Auto-type in the desktop app, and AutoFill on the Mac
date: 2026-10-23
summary: The desktop app can type a login into other apps' windows, after checking the window belongs to it, and on macOS it fills passwords and passkeys in Safari and other apps through the system's AutoFill.
tags: [desktop, security]
---

The desktop app now fills where the browser extension can't reach. See [the desktop app](/docs/platforms/desktop/#auto-type).

- **Auto-type.** In quick access, press Cmd+Enter (Ctrl+Enter) on a login to type it into the window you were in. In any app, `Cmd+Shift+\` (`Ctrl+Shift+\`) types the login that belongs to that window, or lists the matches when there are several. It types the username, Tab, the password and Enter, or a sequence you set on the login, with `{TOTP}` and `{DELAY 500}` for slow apps. Characters like `é` and `ب` work on any keyboard layout.
- **It checks the window first.** In a browser, the page must be on one of the login's websites; a page title never counts, because phishing pages copy them. In other apps, the window or app must be named after the login, or listed in the login's auto-type windows. Octa Pass never types into itself or while the screen is locked, and stops if another window takes focus.
- **Every desktop.** macOS (turn on Octa Pass under Privacy & Security → Accessibility; quick access links there), Windows, Linux on X11, and Wayland through the RemoteDesktop portal. Where nothing can type, Octa Pass copies the password and clears the clipboard after 30 seconds.
- **AutoFill on macOS 14 and later.** An AutoFill extension fills passwords, passkeys and, on macOS 15, one-time codes in Safari and other apps. It asks the running Octa Pass app, which unlocks with Touch ID first and checks that the request comes from its own extension. The extension needs a signed release to be turned on in System Settings; development builds can't be.
