---
title: The extension's Touch ID passkey saves in Octa Pass from Chrome
date: 2026-11-08
summary: Turning on Unlock with Touch ID in the Chrome extension and choosing Octa Pass to save the passkey no longer fails with "Octa Pass saves passkeys for websites only".
tags: [core, extension, mobile]
---

Turning on **Unlock with Touch ID** in the browser extension in Chrome, and choosing Octa Pass when macOS asks where to save the passkey, failed with "Octa Pass saves passkeys for websites only." The 2026-11-07 fix accepted the extension's ID as the passkey's site. Chrome doesn't send the ID, though: it sends the extension's address, `chrome-extension://<id>`. Octa Pass now accepts that address too. Other addresses that aren't websites are still refused. To pick this up, rebuild the Mac app (or the iPhone app). See [plan 05](https://github.com/octapass/octapass/blob/main/plans/05-clients-and-autofill.md).
