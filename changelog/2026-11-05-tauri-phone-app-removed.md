---
title: The phone apps are native only
date: 2026-11-05
summary: The earlier Tauri phone app, which showed the web vault's screens in a web view, is removed. The native iPhone, iPad and Android apps replace it.
tags: [mobile, decision]
---

Octa Pass on phones is now only the native apps: SwiftUI on the iPhone and iPad, Jetpack Compose on Android. The earlier app, built with Tauri, showed the web vault's screens in a web view. It never went to a store, and it's now gone from the repository.

Nothing changes for the native apps. The pieces of the old app they still used have moved:

- The phone vault in Rust is now `crates/octapass-mobile-vault`.
- The core's Swift and Kotlin bindings are now in `apps/ios/Packages/OctaPassCore` and `apps/android/core`.
- The words only the phone apps use are now in `apps/web/src/i18n/phone.ts`, next to the web vault's. That's the file translators edit for the phone apps (see [translations](/docs/contributing/translations/)).

See [mobile](/docs/platforms/mobile/) and the [support matrix](/docs/platforms/support-matrix/). The plan is `plans/17-native-mobile-apps.md`.
