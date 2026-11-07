---
title: The browser extension opens in a tab
date: 2026-11-07
summary: The toolbar button now opens Octa Pass in a browser tab with the web vault's full layout, and the in-page menu, save prompts and passkey prompt are redesigned.
tags: [decision, extension]
---

- **Octa Pass opens in a tab.** The toolbar button opens Octa Pass in a browser tab next to the page you're on, or brings back the Octa Pass tab you already have open. There's no popup and no side panel any more, in Chrome, Edge, Firefox or Safari. The tab has the web vault's full layout: your vaults, categories, sharing, emergency access, masked email, tools, trash, settings and your Health score in the sidebar.
- **This site** comes first in the sidebar. It lists the logins for the tab you came from, with a **Fill** button, and follows the tab you switch to in that window. After **Fill**, you're taken back to the page. **Scan QR code on this page**, **Unlock** in the in-page menu and right-click → **Add one-time code from QR** all work from the tab and bring you back. HTTP sign-in prompts and **Ask on every fill** still open small windows.
- **Account settings in the extension.** Settings now has what the web vault's has for your account: change your master password, show or replace your Secret Key, your vault's keys, the security log, two-step sign-in, your signed-in devices, and the server and storage you use. The Generator's masked email starts with the site you were on.
- **Get the other apps.** A small card at the foot of the sidebar offers the desktop app when your account doesn't have it, and otherwise the phone app. Close it and that app isn't offered again. It never shows in Safari, which comes inside the Mac app.
- **A new in-page menu.** It names the site at the top, shows each login with its site's icon (or a letter until the icon loads), its title and username, separates logins from suggested passwords and masked emails, shows the suggested password in a monospace box, and lists the keys at the foot: ↑↓ Move · ↵ Choose. It's lighter on busy pages too: fewer rescans and icon requests, and suggestions kept for 15 seconds per field.
- **New save prompts.** **Save this login?** and **Update the saved password?** are cards with the site on its own line, the username and a masked password, and a × for Not now. **Never for this site** is a quiet link. Short messages show a progress bar and wait while you point at them.
- **A new passkey prompt.** It names the real site at the top, lists your accounts with their name, username and login, and works with the arrow keys, Enter and Escape. **Use another device or security key** and **Cancel** are at the foot. It sizes itself to fit, shows over a site's open dialog, and loads faster.

See the [browser extension](/docs/platforms/browser-extension/#the-octa-pass-tab), [autofill](/docs/features/autofill/#the-in-page-list) and [passkeys](/docs/features/passkeys/#the-passkey-prompt).
