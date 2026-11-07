---
title: Native desktop apps, starting with the Mac
date: 2026-11-06
summary: The desktop app is moving from a web view to native apps on the same Rust core, starting with a SwiftUI app for macOS.
tags: [decision, desktop]
---

The desktop app shows the web vault's screens in a web view (Tauri). It's moving to native apps, the way the iPhone and Android apps did: **SwiftUI on macOS first**, then Windows and Linux.

- **Same core.** The encryption, sync and every rule about your vault stay in the Rust core. Only the screens change.
- **Shared with iPhone and iPad.** The Mac app is built from the iPhone and iPad app's screens and uses the same vault API, so features and fixes reach all three together.
- **Fewer moving parts next to your open vault.** There's no web view or JavaScript dependency tree in the app that holds your unlocked vault.
- **Windows and Linux keep the current app** until their native ones do everything it does. On the Mac the native app took over the same day ([On a Mac, Octa Pass is now the native app](/changelog/2026-11-06-mac-app-is-native/)).

The plan is [plan 19](https://github.com/octapass/octapass/blob/main/plans/19-native-desktop-apps.md).
