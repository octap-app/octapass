---
title: Touch ID unlock works in Firefox and Safari
date: 2026-10-24
summary: Turning on Unlock with Touch ID in the web vault no longer fails in Firefox and Safari on macOS, and it now takes one fingerprint instead of two.
tags: [security, extension, docs]
---

In Firefox and Safari on macOS, turning on **Settings → Security → Unlock with Touch ID** read your fingerprint and then said "The device prompt was closed". Now it works. Both browsers give the unlock key while the passkey is being created, so one touch is enough. See [device unlock](/docs/features/biometric-unlock/).

- **One prompt where the browser allows it.** Other browsers may still ask twice. If one turns the second prompt down, Settings shows **Finish with Touch ID** to finish with one more click.
- **Clearer errors.** When a device prompt fails, the message now includes what your browser said, so a dismissed prompt and a real problem look different.
- **Firefox 139+ on macOS 15+** is now listed as supported, next to Chrome, Edge and Safari 18+.
- **With the extension installed,** the web vault's Touch ID setup (and any site's request for the PRF extension) goes straight to the browser instead of through the Octa Pass passkey prompt.

Nothing changed in what is stored or sent: the key is still wrapped in your browser, and the server never sees it.

These messages are also in Arabic.
