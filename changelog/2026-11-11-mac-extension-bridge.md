---
title: The browser extension reaches the Mac app again
date: 2026-11-11
summary: In the TestFlight Mac app, browsers couldn't start the small helper the extension talks to, so the lock screen never offered Touch ID through the app. The helper now starts.
tags: [desktop, extension]
---

The extension unlocks through the Mac app with a small helper inside the app, `octapass-native-host`, which your browser starts. In the Mac App Store and TestFlight builds macOS stopped that helper as soon as it started, so the extension never found the app: no **Unlock with Touch ID** on its lock screen, even after **Connect browser extension**.

Every program in a Mac App Store app runs in a sandbox, and a sandboxed helper that a browser starts, instead of its own app, needs its own bundle identifier to set that sandbox up. The helper didn't have one. Now it carries it, and the build stops if it's ever missing.

Nothing else changed: the same browsers are trusted, and the extension still asks the app, which asks for Touch ID. See [unlocking through the desktop app](/docs/platforms/browser-extension/).
