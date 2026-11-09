---
title: Quick access on the Mac finds every item, not just logins
date: 2026-11-09
summary: The Mac app's Cmd+Shift+Space panel now lists cards, identities, notes, Wi-Fi, SSH keys, environments and every other type, grouped by type, with the right thing to copy on Return and the rest under Cmd+K.
tags: [desktop]
---

Quick access in the [Mac app](/docs/platforms/desktop/#quick-access-on-the-mac) only searched logins. Now it searches the whole vault and groups the results by type, as the vault window does: Logins, Cards, Identities, Secure notes, Wi-Fi, SSH keys, Environments, Bank accounts, Crypto wallets and the rest.

- **Return copies what you usually want** from each type: a login's password, a card's number, a Wi-Fi password, an SSH public key, a note's text, an environment as `.env` text, a licence key, a wallet's address.
- **Cmd+K lists everything else** for the selected item (a card's expiry date and security code, a login's username and one-time code, each environment variable), and **Cmd+1 to Cmd+9** run them directly. The vault window's Ctrl+Cmd+C, Shift+Cmd+C and Option+Cmd+C still copy a login's username, password and code.
- **Cmd+O opens the item** in the vault window.
- **A panel that looks like the Mac's own:** no title bar, the system's translucent background in light and dark, a symbol for each type, and right to left in Arabic.

Copying works as before: secrets leave the clipboard after 30 seconds, copying doesn't ask again while the vault is unlocked, and a locked vault offers Touch ID or the vault window. See [plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md).
