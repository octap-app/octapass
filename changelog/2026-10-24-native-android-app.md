---
title: A fully native Android app
date: 2026-10-24
summary: The Android app is rebuilt in Jetpack Compose, with every screen native and every feature of the current app, on the same Rust core.
tags: [mobile]
---

The Android app is now a native Jetpack Compose app (`apps/android`), with nothing shown in a web view. It has every feature the current phone app has, in the same order and with the same words as the native iPhone app:

- **Getting started:** create an account with your invite, save, share or print your Recovery Kit, sign in on a new phone with two-step sign-in (an authenticator or a recovery code), and unlock with your fingerprint, face or screen lock, offered right after you sign in.
- **Your vault:** the Sort and group menu, websites with several accounts grouped in one row, search, categories including One-time codes and Wi-Fi, favourites, trash and website icons (through your own server, if you turn them on).
- **Every item type**, with files from the camera, photos or your files, Wi-Fi **Connect** and QR codes, masked email, recovery info, the generator, and copying that clears the clipboard after 30 seconds.
- **Scan a QR code** with the camera, a photo or an image file. One-time codes, Google Authenticator exports and setup links other apps open Octa Pass with are reviewed first, so you choose which login each code joins.
- **Health** and the recovery map, sharing, families, share links, emergency access, import and export (including moving to and from other password managers), devices, the security log and deleting your account.

It follows Android's font size, dark theme and right-to-left layout for Arabic, uses predictive back and puts the item beside the list on tablets. Other apps' autofill services can't read its fields. The Autofill and Credential Manager services are the ones the current app uses, moved in unchanged.

The current app stays until the native one is released. See [Mobile apps](/docs/platforms/mobile/). Like the current app, it has run on the Android emulator, not yet on phones.
