---
title: The iPhone app can set up your one-time codes, and both phone apps turn AutoFill on for you
date: 2026-10-24
summary: Octa Pass can be the iPhone's app for one-time code setup links and QR codes, and the phone apps have a button that turns AutoFill on.
tags: [mobile, ios, android]
---

## What's new

- **Set Up Codes In.** Octa Pass now appears under Settings → General → AutoFill & Passwords → Set Up Codes In on the iPhone. Choose it, and `otpauth://` setup links and their QR codes (from Safari or the Camera app) open in Octa Pass, as do Google Authenticator export QR codes. Octa Pass asks before it adds a code, then adds it to the login with the same name or as a new login. See [setting up one-time codes](/docs/platforms/mobile/#setting-up-one-time-codes-on-the-iphone).
- **Turn on AutoFill.** The item list shows a **Turn on AutoFill** prompt until Octa Pass fills for you, and **Settings → AutoFill** shows whether it's on. On iOS 18 the system asks right there; on iOS 17 and Android it opens the right settings page. Android 14+ also has a button for Passwords, passkeys & accounts.
- **Building for your own iPhone.** `apps/mobile/scripts/ios-device.sh` builds a development-signed app and installs it on a connected iPhone. Your Apple team comes from `APPLE_DEVELOPMENT_TEAM` or a gitignored `ios-device.env`, and now signs the AutoFill extension too.
