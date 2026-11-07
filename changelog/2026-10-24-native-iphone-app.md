---
title: A fully native iPhone and iPad app
date: 2026-10-24
summary: The iPhone and iPad app is rebuilt in SwiftUI, with every screen native, on the same Rust core as the native Android app.
tags: [mobile]
---

The iPhone and iPad app is now a native SwiftUI app (`apps/ios`), with nothing shown in a web view. It has the same screens, in the same order and with the same words, as the native Android app:

- **Getting started:** create an account with your invite, save, share or print your Recovery Kit, sign in on a new device with two-step sign-in (an authenticator or a recovery code), and unlock with Face ID, Touch ID or your passcode, offered right after you sign in.
- **Your vault:** the Sort and group menu, websites with several accounts in one row that opens in place, search, the vault's lists and categories (including One-time codes and Wi-Fi), favourites and the trash from a swipe, and website icons through your own server.
- **Every item type**, with files from the camera, Photos or Files that open in Quick Look, Wi-Fi **Connect** and QR codes, masked email in the login editor, recovery info, the generator, and copying that clears the clipboard after 30 seconds and never goes to your other devices.
- **Scan a QR code** with the camera, a photo or an image file. One-time codes, Google Authenticator exports and setup links (Set Up Codes In) are reviewed first, so you choose which login each code joins. Logins get **Add one-time code**, and codes on an item of their own **Link to a login**.
- **Health** and the recovery map, sharing with fingerprints to compare, families, share links, emergency access, import and export, devices, the security log, two-step sign-in settings and deleting your account.

It follows Dynamic Type, dark mode and right-to-left layout for Arabic, works with VoiceOver, and on iPad shows the vault's lists in a sidebar next to the list and the item. The app switcher shows a cover instead of the vault. The AutoFill extension is the one the current app uses, moved in unchanged.

The current app stays until the native one is released. See [Mobile apps](/docs/platforms/mobile/). It has run on the iOS Simulator, not yet on a phone.
