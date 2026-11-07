---
title: Octa Pass on the Mac under AutoFill from and Set up codes in
date: 2026-11-04
summary: The Mac app now opens one-time code setup links, which lists it under Set up codes in on macOS 15, and builds made with pnpm build:macos sign the AutoFill extension so macOS lists it under AutoFill from.
tags: [desktop, docs]
---

On the iPhone, Octa Pass showed up in Settings → General → AutoFill & Passwords under **AutoFill From** and **Set Up Codes In**. On the Mac it showed up in neither.

- **Set up codes in (macOS 15).** The Mac app now opens one-time code setup links (`otpauth://`) and Google Authenticator exports (`otpauth-migration://`), which is what macOS lists there. When one opens it, Octa Pass comes forward, asks you to unlock if it's locked, and shows the code before adding anything, because any website can open such a link. Then you choose which login it joins, as for a scanned QR code. See [setting up one-time codes on the Mac](/docs/platforms/desktop/#setting-up-one-time-codes-on-the-mac).
- **AutoFill from.** macOS lists the AutoFill extension only when an Apple developer team signs it, and the app has to be signed by the same team. Builds signed by hand signed the app but not the extension. Now the extension is always signed with the app's team, and `pnpm build:macos` signs both with the team your iPhone builds use. Xcode makes the extension's provisioning profile, as it does for the iPhone. See [building the apps](/docs/contributing/development-setup/#build-the-apps).

Windows and Linux don't open these links yet. The new messages are also in Arabic.
