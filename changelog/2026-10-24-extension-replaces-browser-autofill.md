---
title: The extension can replace the browser's password manager, and saves addresses and cards
date: 2026-10-24
summary: One switch turns off Chrome's or Edge's own offers to save passwords, addresses and cards (passwords in Firefox), and the extension now offers to save the addresses and cards you type into websites.
tags: [extension]
---

Two gaps found while testing the extension on a vault on this device only: the browser kept offering to save what Octa Pass saves, and Chrome offered to save an address Octa Pass didn't.

## What's new

- **Use Octa Pass instead of the browser's password manager.** In the extension's settings, and suggested once after you first unlock. In Chrome and Edge it turns off the browser's password saving, address autofill and card autofill, each one your choice. Firefox only lets extensions turn off password saving; Safari lets them change none of it, so the settings show where to do it. It asks for the `privacy` permission only when you turn it on, says so if another extension or a policy controls a setting, and gives the browser its settings back when you turn it off. See [turning off the browser's own password manager](/docs/platforms/browser-extension/#turning-off-the-browsers-own-password-manager).
- **Save addresses and cards.** Send an address or card form and Octa Pass asks **Save this address in Octa Pass?** or **Save this card in Octa Pass?**, or offers **Update** when a saved Identity or Card matches. Only the fields Octa Pass recognised are read, the security code is saved only if you tick the box, and nothing is offered on plain `http://` pages or in frames from other sites you haven't allowed. See [saving addresses and cards](/docs/features/autofill/#saving-addresses-and-cards).
- **Never for this site** is on every save prompt now, logins included. **Settings → Never offered to save** lists those sites.
