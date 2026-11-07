---
title: An open vault doesn't ask to reveal or copy
date: 2026-11-06
summary: While Octa Pass is unlocked, revealing and copying never ask for Face ID or your master password, however it was opened. Exporting, your Secret Key and your account settings still ask every time.
tags: [decision, security, mobile, desktop, extension]
---

Revealing or copying a password could still ask for Face ID every time, for example after turning **Stay unlocked** off while the app was open, or with **Use device auth when Octa Pass opens** off. With Stay unlocked on, the first reveal asked too. Once Octa Pass is open, that's a prompt too many.

Now, while Octa Pass is unlocked, these never ask:

- revealing and copying a password or any other field
- showing an item as a QR code
- showing an SSH key or an environment's values

It doesn't matter how Octa Pass was opened: Face ID, your fingerprint, your device's lock, your master password or Stay unlocked. Once it locks, unlocking it again is the only prompt.

These still ask every time, with your device's lock or your master password:

- exporting your vault
- saving a private key or an `.env` file
- your Secret Key, Recovery Kit and recovery code
- changing or resetting your master password
- rotating keys
- deleting your account

This applies in the iPhone, iPad and Android apps, the desktop app, the web vault and the browser extension.
