---
title: The desktop apps offer the browser extension
date: 2026-11-09
summary: Until the Octa Pass extension has reached the Mac, Windows or Linux app, a small card in the vault window offers it for the browsers on your computer, and Settings → Browser extension always has the links.
tags: [desktop, extension, docs]
---

The browser extension unlocks through the desktop app, but nothing in the app said so until you went looking. Now:

- **A card in the vault window.** At the foot of the sidebar, **Fill passwords in your browser** has a **Get it for …** link for each browser on this computer that the extension connects from: Chrome, Edge, Brave, Chromium and Firefox. On the Mac a link opens in that browser. If no browser is connected yet, the card also offers to connect. Close it with × and it stays closed on this computer.
- **Connect, when it can't reach the app.** If the extension has come before but no browser is connected now, the card says **Connect the browser extension** instead.
- **Settings → Browser extension** always has the links, says which browsers are connected and which the extension has reached the app from, and has Connect and Disconnect. It's new in the Windows and Linux app, where only the Browser menu had them. On the Mac it also links to Safari's extension.

**How the app knows:** the first time an Octa Pass extension asks the app anything, the app notes the browser's name and the date in its own data folder, for this computer only. It isn't synced and holds no secrets. The Mac app is sandboxed and can't look in the browsers' profiles, so this is how it tells.

The extension isn't in any browser store yet, so every link goes to the [browser extension](/docs/platforms/browser-extension/) page, which says how to install it. See [getting the extension](/docs/platforms/desktop/#getting-the-extension).
