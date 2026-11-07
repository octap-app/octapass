---
title: Passkey provider for Windows 11
date: 2026-11-02
summary: The desktop app can act as a passkey provider on Windows 11, off by default and asking for Windows Hello on every use. Not yet tried on real Windows.
tags: [desktop, security]
---

The desktop app now has a [passkey provider for Windows 11](/docs/features/passkeys/#windows-11), so Windows' own passkey dialog and browser autofill can offer your Octa Pass passkeys.

It's off by default and per device. Turn on **Use Octa Pass as a passkey provider** in Settings, then turn on Octa Pass in Windows Settings. It needs Windows 11 24H2 (26100.6725) or 25H2 (26200.6725) or newer, and the app's MSIX package: on the current installer the setting doesn't appear, and passkeys keep working through the browser extension.

Every use asks for Windows Hello, whatever the site requests. Octa Pass checks Windows' signature on each request before reading it and on the Hello result before signing. Keys never leave the vault; Windows gets only a list of sites and user names to offer, kept on this device and cleared when you turn the provider off or sign out.

**Not yet tried on real Windows.** The logic is tested against a stand-in for Windows and the Windows code compiles, but nothing has run there, and the signed package isn't released. Design and reasons: [plan 05](https://github.com/octapass/octapass/blob/main/plans/05-clients-and-autofill.md).
