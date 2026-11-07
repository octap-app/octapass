---
title: Android app preview with Autofill, Credential Manager and Wi-Fi Connect
date: 2026-10-24
summary: The Octa Pass Android app runs on the Android emulator, with fingerprint or screen-lock unlock, an Autofill service with suggested passwords, a Credential Manager provider for passwords and passkeys, Wi-Fi Connect and QR codes.
tags: [mobile, security]
---

The Android app joins the iPhone app in `apps/mobile` (Tauri 2). It shows the web vault's screens, while the vault, its keys and the sync run natively in the app, on the Rust core.

- Sign up, sign in, every item type, sync and the trash, offline unlock from the encrypted store on the phone.
- Unlock with your fingerprint or face, or your screen-lock PIN, pattern or password. The secret that unlocks the vault is encrypted to an Android Keystore key (StrongBox when the phone has it) that only works after that check, and a new fingerprint or face invalidates it.
- Autofill in other apps and browsers: pick Octa Pass in the keyboard's suggestions or the dropdown, confirm with your fingerprint or screen lock, and the login saved for that app or website is filled. Sign-up forms get a suggested strong password, made on the phone, and passwords you type can be saved.
- Credential Manager on Android 14+: your logins and passkeys appear in the system sheet. Apps only get a website's passkeys when the website lists them in its Digital Asset Links.
- Wi-Fi Connect saves a network after Android's confirmation; QR codes are shown and scanned on the phone. Screenshots are blocked in the app.

It's a preview: it has run on the Android emulator, not on phones, and there are no Google Play builds yet. See [Mobile apps](/docs/platforms/mobile/).
