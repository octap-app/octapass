---
title: The desktop app only answers its own native host, started by a real browser
date: 2026-10-24
summary: Other programs on your computer can no longer ask the desktop app for your account key by pretending to be the Octa Pass browser extension.
tags: [desktop, extension, security]
---

An independent security review found that the desktop app believed whatever extension name arrived on its local socket. Any program running as you could connect, claim to be the Octa Pass extension and ask for the account key; if you then confirmed the Touch ID prompt, that program would get the key. It could also start the app's own native messaging host and hand it a made-up extension name.

Both ends now check who they're talking to:

- **The app** answers only the `octapass-native-host` that ships next to it. It finds out which program connected from the operating system (the process's audit token on macOS, its process ID on Linux and Windows), not from anything that program says. Signed macOS builds also check that the host carries the same developer signature as the app.
- **The host** relays requests only when a supported browser started it: Chrome, Chromium, Edge, Brave, Firefox, Vivaldi, Opera or Arc. Release builds check that the browser is signed by its maker on macOS and Windows, or installed system-wide on Linux. The app runs the same check on the host's browser, so a tampered host doesn't get around it.
- **The Touch ID prompt names the browser**: "unlock Octa Pass in Google Chrome".
- **Only the published extension** may connect in release builds. Development builds also accept the development extension ID, and they say on the console that they skip the signature checks.

If something other than a supported browser starts the host, every request gets a `browserNotTrusted` error, with a message the extension can show. Chromium on macOS and Windows isn't signed by a vendor, so release builds there don't accept it. See [the desktop app](/docs/platforms/desktop/) and [the browser extension](/docs/platforms/browser-extension/); the details for contributors are in `apps/desktop/README.md`.
