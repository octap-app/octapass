---
title: On a Mac, Octa Pass is now the native app
date: 2026-11-06
summary: The native SwiftUI Mac app replaces the Tauri desktop app on macOS; the Tauri app stays on Windows and Linux.
tags: [decision, desktop]
---

The Mac app is now the native one, built from the iPhone and iPad app's screens. The earlier Mac version of the desktop app (Tauri, the web vault's screens in a web view) is gone: it no longer builds, and its AutoFill and Safes extensions went with it.

- **What the Mac app does:** sign in or sign up, unlock with Touch ID or your Mac password, every item type, AutoFill of passwords, passkeys and codes even with the app closed, Safes in Finder, one-time code links, Credential Exchange with other password managers, quick access from the menu bar and opening at login. It also unlocks the browser extension and the CLI, and runs the SSH agent ([the Mac app works with the browser extension, the CLI and SSH](/changelog/2026-11-06-mac-browser-extension-cli-ssh-agent/)).
- **Not there yet:** auto-type, Wi-Fi and single sign-on.
- **Moving over:** there's no automatic migration. Sign in again in the new app and your account syncs. A vault without an account needs exporting from the old app and importing in the new one.
- **Downloads:** there are no signed Mac downloads yet. `pnpm build:macos` builds the app, signed for development.
- **Windows and Linux** keep the Tauri app until their native apps are ready.

See the [desktop apps](/docs/platforms/desktop/) page and [plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md).
