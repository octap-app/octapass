---
title: The core for the iPhone and Android apps
date: 2026-10-24
summary: The Octa Pass core now has Swift and Kotlin bindings, so the mobile apps and their autofill extensions can sign in, unlock with Face ID, a fingerprint or the device passcode, fill passwords and codes, and use passkeys.
tags: [core, mobile, security]
---

The iPhone and Android apps fill passwords from small system extensions: the iOS AutoFill Credential Provider and the Android Autofill and Credential Manager services. They use the same Rust core as the web vault, through new Swift (`OctaPassCore`) and Kotlin (`app.octap.core`) bindings. The apps themselves come next.

## What the bindings do

- **Sign up, sign in, sync and save** against an Octa Pass server. Requests go through the phone's own networking (`URLSession`, OkHttp). An edit that clashes with one made on another device is kept as a "conflicting copy", so nothing is lost.
- **Unlock with the device's own lock**: Face ID, Touch ID or a fingerprint, or the device passcode when there's no biometric. The master password is asked for again every 14 days.
- **Share one encrypted file** between the app and its extensions. It holds only what the server holds: every secret in it is still encrypted.
- **Fill on the right site only.** Logins match on the site's registrable domain from the Public Suffix List, so `paypal.com.evil.io` never gets your PayPal password. Android apps match only their own package.
- **One-time codes, the password generator and passkeys.** Passkeys work with what iOS and Android hand to a password manager: the system's hash of the sign-in request, or the request an Android app sends. A new passkey is saved before the site gets it, and its private key never leaves the core.

## How it's tested

The same flow runs in Rust, Swift and Kotlin: sign up, sign in on a second device, save and read a login, generate a code, and create and use a passkey. It runs against an in-process test server that uses the real OPAQUE login. Passkey signatures are checked by independent verifiers (CryptoKit on Apple platforms, Java's security library on Android's side). See `crates/octapass-ffi/README.md` for the API and the file format.
