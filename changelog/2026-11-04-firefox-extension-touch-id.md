---
title: Touch ID in the Firefox extension goes through the desktop app
date: 2026-11-04
summary: In the Firefox extension, Settings → Security no longer offers an Unlock with Touch ID switch that failed with "The operation is insecure". It links to the desktop app instead.
tags: [extension, security, docs]
---

In the Octa Pass extension for Firefox, turning on **Settings → Security → Unlock with Touch ID** failed with "SecurityError: The operation is insecure".

Firefox lets an extension use passkeys only for a website it has access to, not for the extension itself. The passkey that unlocks Octa Pass belongs to the page that makes it, so Firefox refuses it in the extension. Touch ID still works in the [web vault](/docs/features/biometric-unlock/#web-vault) in Firefox.

- **In Firefox,** the setting now explains this and links to the [desktop app](/docs/platforms/desktop/). With the app running and signed in to the same account, the extension's lock screen offers **Unlock with Touch ID in the desktop app**.
- **Clearer message elsewhere.** If a browser refuses a device passkey for a page's address, Octa Pass now says the browser can't unlock with your device there, instead of asking you to try again or saying device unlock stopped working.
- Chrome and Edge are unchanged.

Nothing changed in what is stored or sent. See [biometric unlock in the browser extension](/docs/features/biometric-unlock/#browser-extension-prf).

These messages are also in Arabic.
