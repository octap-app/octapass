---
title: The extension asks before filling forms from other sites
date: 2026-10-23
summary: A sign-in or payment form that a site shows from another site now needs your approval before Octa Pass fills it, and the extension says when the desktop app doesn't recognise your browser.
tags: [extension, desktop, security]
---

Two changes from the second security review of the browser extension.

## Forms from other sites

Some pages show a form from another site inside them, such as a sign-in box from an identity provider or a payment form. Until now Octa Pass offered its menu there like anywhere else. Now the menu asks first: *This form is from accounts.example-idp.com, inside shop.example. Allow Octa Pass here?* Both names come from the browser, not from the page.

- Your answer is remembered for that frame on that site only.
- An allowed frame gets the logins saved for its own site, never the page's.
- Frames from the page's own site, like `login.shop.example` inside `shop.example`, don't ask.
- **Settings → Frames from other sites** lists what you allowed, and you can remove any of them.

See [forms from other sites](/docs/platforms/browser-extension/#forms-from-other-sites).

## "Desktop app not running" when it was

The desktop app only unlocks the extension in browsers it recognises, signed by their makers. In any other browser the extension used to act as if the app wasn't running. Now the lock screen says *The Octa Pass app doesn't recognise this browser, so it can't unlock it. Unlock with your master password.* It links to the [list of supported browsers](/docs/platforms/desktop/#supported-browsers).
