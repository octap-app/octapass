---
title: iPhone builds for App Store Connect
date: 2026-11-04
summary: pnpm build:ios now signs the iPhone app for App Store Connect and can upload it, and the app carries the privacy manifest and permission texts the App Store asks for.
tags: [mobile, release]
---

Uploading the iPhone app to App Store Connect failed with "Invalid Provisioning Profile … A distribution provisioning profile should be used" (90161). The build was signed for development, which App Store Connect doesn't accept.

- **`pnpm build:ios`** now exports the build for App Store Connect, signed for distribution, as `apps/ios/build/AppStore/Octa Pass.ipa`. **`pnpm build:ios --upload`** uploads it directly. Xcode makes the distribution certificate and profiles itself, and picks a build number above the ones already uploaded.
- **Privacy manifests** for the app and its AutoFill extension say why they use the system APIs Apple asks about, and that the app collects only your account's email address, to sign you in. There's no tracking.
- **Permission texts** cover everything the app can ask for: the camera, Face ID, location (only for the Wi-Fi network's name) and the local network (for a server you host at home). They're also in Arabic.

See [building the apps](/docs/contributing/development-setup/#build-the-apps); the details are in `apps/ios/README.md`.
