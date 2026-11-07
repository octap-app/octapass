---
title: Move between password managers on Android, without a file
date: 2026-10-24
summary: On Android, import into Octa Pass from Google Password Manager and other password managers on the phone, or let them take your items from Octa Pass, through Credential Manager's credential transfer.
tags: [mobile, core, security, docs]
---

Android lets password managers hand their items to each other directly, in the FIDO Credential Exchange Format (CXF), with Google Play services in the middle and no export file left on the phone. Octa Pass for Android now does both sides.

**Import.** **Settings → Other password managers → Import from another app** shows the apps that can hand over their items. Pick one, and Octa Pass shows what it sent (logins, passkeys, cards and so on, and anything that can't come across) before anything is saved. Tap **Import** to add them to your Personal vault, or cancel and they're gone.

**Export.** In another password manager, choose to import and pick **Octa Pass**. Octa Pass names the app that asked and wants your master password, like every export, then hands over only the kinds of items that app asked for.

The items stay in Octa Pass's Rust core the whole way: the app's screens only see how many there are. It needs Google Play services. See [moving between password managers on Android](/docs/platforms/mobile/#moving-between-password-managers-on-android).
